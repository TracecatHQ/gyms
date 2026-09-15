set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

root := justfile_directory()
provider_version := "0.1.0"

default:
    @just --list

provider:
    #!/usr/bin/env bash
    set -euo pipefail
    os="$(go env GOOS)"
    arch="$(go env GOARCH)"
    destination="{{ root }}/.terraform.d/plugins/registry.terraform.io/tracecathq/tracecat/{{ provider_version }}/${os}_${arch}"
    mkdir -p "$destination"
    cd "{{ root }}/terraform-provider-tracecat"
    GOCACHE="{{ root }}/.cache/go-build" go build -o "$destination/terraform-provider-tracecat_v{{ provider_version }}" .

# Build the local provider and initialize one lab, or every lab when omitted.
init lab="": provider
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "{{ lab }}" ]]; then
      labs=("{{ lab }}")
    else
      labs=()
      for terraform_dir in "{{ root }}"/[0-9][0-9][0-9]/terraform; do
        [[ -d "$terraform_dir" ]] || continue
        labs+=("$(basename "$(dirname "$terraform_dir")")")
      done
    fi
    for current in "${labs[@]}"; do
      test -d "{{ root }}/$current/terraform" || { echo "Unknown lab: $current" >&2; exit 2; }
      rm -f "{{ root }}/$current/terraform/.terraform.lock.hcl"
      terraform -chdir="{{ root }}/$current/terraform" init -upgrade -plugin-dir="{{ root }}/.terraform.d/plugins"
    done

# Cache and start the exact public Tracecat release, then enable API access.
tracecat-up:
    #!/usr/bin/env bash
    set -euo pipefail
    version="${TRACECAT_VERSION:?set TRACECAT_VERSION in .env}"
    checkout="{{ root }}/.cache/tracecat"
    if [[ ! -d "$checkout/.git" ]]; then
      mkdir -p "{{ root }}/.cache"
      git clone --depth 1 --branch "$version" https://github.com/TracecatHQ/tracecat.git "$checkout"
    fi
    test "$(git -C "$checkout" describe --tags --exact-match)" = "$version" || { echo "Cached Tracecat checkout does not match $version; remove .cache/tracecat to change versions." >&2; exit 2; }
    compose=(docker compose --project-directory "$checkout" --env-file "$checkout/.env.example" --env-file "{{ root }}/.env" -f "$checkout/docker-compose.yml")
    "${compose[@]}" up --wait --wait-timeout 180
    entitlements="$(
      "${compose[@]}" exec -T postgres_db psql --username postgres --dbname postgres --quiet --tuples-only --no-align --set ON_ERROR_STOP=1 <<'SQL'
    DO $seed$
    BEGIN
      IF (SELECT count(*) FROM tier WHERE is_default IS TRUE AND is_active IS TRUE) <> 1 THEN
        RAISE EXCEPTION 'expected exactly one active default tier';
      END IF;
      UPDATE tier
      SET entitlements = '{"service_accounts": true}'::jsonb
      WHERE is_default IS TRUE AND is_active IS TRUE;
    END
    $seed$;
    SELECT entitlements::text
    FROM tier
    WHERE is_default IS TRUE AND is_active IS TRUE;
    SQL
    )"
    test "$entitlements" = '{"service_accounts": true}' || { echo "Failed to seed the service_accounts entitlement" >&2; exit 2; }

tracecat-down:
    #!/usr/bin/env bash
    set -euo pipefail
    checkout="{{ root }}/.cache/tracecat"
    test -f "$checkout/docker-compose.yml" || exit 0
    docker compose --project-directory "$checkout" --env-file "$checkout/.env.example" --env-file "{{ root }}/.env" -f "$checkout/docker-compose.yml" down

# Start a lab's target services. Tracecat must already be running.
up lab:
    @docker compose --project-directory "{{ root }}/{{ lab }}" --env-file "{{ root }}/.env" -p "lab-{{ lab }}" -f "{{ root }}/{{ lab }}/compose.yml" up -d

down lab:
    @docker compose --project-directory "{{ root }}/{{ lab }}" --env-file "{{ root }}/.env" -p "lab-{{ lab }}" -f "{{ root }}/{{ lab }}/compose.yml" down

_terraform lab command:
    #!/usr/bin/env bash
    set -euo pipefail
    manifest="{{ root }}/{{ lab }}/tracecat/tracecat.json"
    mcp_credentials="$(jq -c '
      reduce (.mcp_integrations[]? | select(.credentials_from_env)) as $integration ({};
        .[$integration.catalog_slug] = reduce ($integration.credentials_from_env | to_entries[]) as $credential ({};
          .[$credential.key] = (env[$credential.value] // error("set " + $credential.value))))
    ' "$manifest")"
    secret_values="$(jq -c '
      reduce (.secrets[]? | select(.keys_from_env)) as $secret ({};
        .[$secret.name] = reduce ($secret.keys_from_env | to_entries[]) as $key ({};
          .[$key.key] = (env[$key.value] // error("set " + $key.value))))
    ' "$manifest")"
    candidate_model="$(jq -cn --arg provider "$CANDIDATE_MODEL_PROVIDER" --arg name "$CANDIDATE_MODEL_NAME" '{provider:$provider,name:$name}')"
    judge_model="$(jq -cn --arg provider "$JUDGE_MODEL_PROVIDER" --arg name "$JUDGE_MODEL_NAME" '{provider:$provider,name:$name}')"
    export TF_VAR_mcp_credentials="$mcp_credentials"
    export TF_VAR_secret_values="$secret_values"
    export TF_VAR_candidate_model="$candidate_model"
    export TF_VAR_judge_model="$judge_model"
    terraform -chdir="{{ root }}/{{ lab }}/terraform" "{{ command }}"

plan lab:
    @just _terraform "{{ lab }}" plan

apply lab:
    @just _terraform "{{ lab }}" apply

# Trigger Candidate Run asynchronously. Optional: CASE_IDS=a,b.
run lab CASE_IDS="":
    #!/usr/bin/env bash
    set -euo pipefail
    workspace_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -raw workspace_id)"
    workflow_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -json workflow_ids | jq -r .candidate_run)"
    case_ids_value="{{ CASE_IDS }}"
    case_ids_value="${case_ids_value#CASE_IDS=}"
    case_ids="$(jq -cn --arg value "$case_ids_value" '$value | if length == 0 then [] else split(",") end')"
    payload="$(jq -cn --arg workflow_id "$workflow_id" --argjson case_ids "$case_ids" '{workflow_id:$workflow_id,inputs:{case_ids:$case_ids}}')"
    response="$(curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" -H 'Content-Type: application/json' -d "$payload" "$TRACECAT_API_URL/workspaces/$workspace_id/workflow-executions")"
    echo "$response" | jq '{evaluation_run_id:.wf_exec_id}'

# Trigger Judge Run asynchronously for one Evaluation Run.
judge lab RUN_ID:
    #!/usr/bin/env bash
    set -euo pipefail
    workspace_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -raw workspace_id)"
    workflow_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -json workflow_ids | jq -r .judge_run)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    payload="$(jq -cn --arg workflow_id "$workflow_id" --arg run_id "$run_id" '{workflow_id:$workflow_id,inputs:{evaluation_run_id:$run_id}}')"
    response="$(curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" -H 'Content-Type: application/json' -d "$payload" "$TRACECAT_API_URL/workspaces/$workspace_id/workflow-executions")"
    echo "$response" | jq --arg run_id "$run_id" '{evaluation_run_id:$run_id,judge_run_execution_id:.wf_exec_id}'

status lab RUN_ID:
    #!/usr/bin/env bash
    set -euo pipefail
    workspace_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -raw workspace_id)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    workflow_id="${run_id%%/*}"
    execution_id="${run_id#*/}"
    test "$workflow_id" != "$execution_id" || { echo "RUN_ID must be a Tracecat workflow execution ID" >&2; exit 2; }
    curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" "$TRACECAT_API_URL/workspaces/$workspace_id/workflows/$workflow_id/executions/$execution_id" | jq '{id,status,start_time,close_time}'

# Export criterion rows to NNN/results/<run-id>/scores.csv.
export lab RUN_ID:
    #!/usr/bin/env bash
    set -euo pipefail
    workspace_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -raw workspace_id)"
    table_id="$(terraform -chdir="{{ root }}/{{ lab }}/terraform" output -json table_ids | jq -r .evaluation_scores)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    destination="{{ root }}/{{ lab }}/results/$run_id/scores.csv"
    rows_file="$(mktemp)"
    csv_file="$(mktemp)"
    trap 'rm -f "$rows_file" "$csv_file"' EXIT
    cursor=""
    while true; do
      query=(--get --data-urlencode "limit=200")
      if [[ -n "$cursor" ]]; then
        query+=(--data-urlencode "cursor=$cursor")
      fi
      response="$(curl -fsS "${query[@]}" -H "Authorization: Bearer $TRACECAT_API_KEY" "$TRACECAT_API_URL/workspaces/$workspace_id/tables/$table_id/rows")"
      jq -c '.items[]' <<<"$response" >> "$rows_file"
      [[ "$(jq -r '.has_more' <<<"$response")" = true ]] || break
      cursor="$(jq -er '.next_cursor' <<<"$response")"
    done
    if ! jq -se --arg run_id "$run_id" 'any(.evaluation_run_id == $run_id)' "$rows_file" >/dev/null; then
      echo "No completed Judge Run scores found for $run_id" >&2
      exit 2
    fi
    jq -sr --arg run_id "$run_id" '
      ["schema_version","lab_id","evaluation_run_id","trial_id","case_id","trial_number","candidate_session_id","judge_run_execution_id","judge_session_id","rubric_id","rubric_version","criterion_id","criterion_weight","criterion_result","criterion_points","criterion_hard_gate","trial_hard_failed","trial_score","reason","evidence_refs","candidate_completed_at","judged_at"],
      ((map(select(.evaluation_run_id == $run_id)) | sort_by(.case_id, .trial_number, .criterion_id))[] | [.schema_version,.lab_id,.evaluation_run_id,.trial_id,.case_id,.trial_number,.candidate_session_id,.judge_run_execution_id,.judge_session_id,.rubric_id,.rubric_version,.criterion_id,.criterion_weight,.criterion_result,.criterion_points,.criterion_hard_gate,.trial_hard_failed,.trial_score,.reason,(.evidence_refs|tojson),.candidate_completed_at,.judged_at]) | @csv' "$rows_file" > "$csv_file"
    mkdir -p "$(dirname "$destination")"
    mv "$csv_file" "$destination"
    echo "$destination"

check:
    #!/usr/bin/env bash
    set -euo pipefail
    grep -Fxq 'TRACECAT_VERSION=1.0.0-rc.1' "{{ root }}/.env.example"
    ! grep -q '^TRACECAT__FEATURE_FLAGS=' "{{ root }}/.env.example"
    grep -Fxq 'TRACECAT__EE_MULTI_TENANT=true' "{{ root }}/.env.example"
    found=0
    for lab_dir in "{{ root }}"/[0-9][0-9][0-9]; do
      [[ -d "$lab_dir/terraform" ]] || continue
      found=1
      lab="$(basename "$lab_dir")"
      jq -e '
        .schema_version == 1 and
        ([.agent_presets[].slug] | sort) == ["candidate", "judge"]
      ' "{{ root }}/$lab/tracecat/tracecat.json" >/dev/null
      jq -e . "{{ root }}/$lab/evals/rubric.json" >/dev/null
      jq -cs --slurpfile rubric "{{ root }}/$lab/evals/rubric.json" '
        (length > 0 and length <= 200) and
        ($rubric[0].schema_version == 1) and
        (($rubric[0].rubric_id | type) == "string") and
        (($rubric[0].rubric_version | type) == "number") and
        (($rubric[0].criteria | map(.criterion_id) | length) == ($rubric[0].criteria | map(.criterion_id) | unique | length)) and
        (map(.case_id) | length == (unique | length)) and
        (all(.[]; .schema_version == 1 and (.case_id | type) == "string" and (.case | type) == "object" and (.oracle.criteria | type) == "object")) and
        (all(.[]; (.oracle.criteria | keys | sort) == ($rubric[0].criteria | map(.criterion_id) | sort))) and
        (all($rubric[0].criteria[]; (.criterion_id | type) == "string" and (.weight | type) == "number" and .weight >= 0 and (.hard_gate | type) == "boolean")) and
        (($rubric[0].criteria | map(select(.hard_gate == false) | .weight) | add) == 100) and
        (all($rubric[0].criteria[]; if .hard_gate then .weight == 0 else true end))
      ' "{{ root }}/$lab/evals/cases.ndjson" >/dev/null
      for heading in "Task" "Scoring" "Target" "Agent access" "Run"; do
        grep -Fxq "## $heading" "{{ root }}/$lab/README.md"
      done
    done
    test "$found" = 1
    ruby -e 'require "yaml"; ARGV.flat_map { |pattern| Dir[pattern] }.each { |path| YAML.load_file(path) }' "{{ root }}/terraform/modules/lab/workflows/*.yml" "{{ root }}/[0-9][0-9][0-9]/tracecat/workflows/*.yml"
    terraform fmt -check -recursive "{{ root }}"
    cd "{{ root }}/terraform-provider-tracecat"
    GOCACHE="{{ root }}/.cache/go-build" go test ./...
