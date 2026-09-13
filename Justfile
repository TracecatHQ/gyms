set shell := ["bash", "-eu", "-o", "pipefail", "-c"]
set dotenv-load := true

root := justfile_directory()
provider_version := "0.1.0"

default:
    @just --list

provider:
    #!/usr/bin/env bash
    os="$(go env GOOS)"
    arch="$(go env GOARCH)"
    destination="{{ root }}/.terraform.d/plugins/registry.terraform.io/tracecathq/tracecat/{{ provider_version }}/${os}_${arch}"
    mkdir -p "$destination"
    cd "{{ root }}/terraform-provider-tracecat"
    GOCACHE="{{ root }}/.cache/go-build" go build -o "$destination/terraform-provider-tracecat_v{{ provider_version }}" .

# Build the local provider and initialize one gym, or every gym when omitted.
init gym="": provider
    #!/usr/bin/env bash
    gyms="${gym:-001 002 003}"
    for current in $gyms; do
      test -d "{{ root }}/$current/terraform" || { echo "Unknown gym: $current" >&2; exit 2; }
      rm -f "{{ root }}/$current/terraform/.terraform.lock.hcl"
      terraform -chdir="{{ root }}/$current/terraform" init -upgrade -plugin-dir="{{ root }}/.terraform.d/plugins"
    done

# Cache and start the exact public Tracecat release.
tracecat-up:
    #!/usr/bin/env bash
    version="${TRACECAT_VERSION:?set TRACECAT_VERSION in .env}"
    checkout="{{ root }}/.cache/tracecat"
    if [[ ! -d "$checkout/.git" ]]; then
      mkdir -p "{{ root }}/.cache"
      git clone --depth 1 --branch "$version" https://github.com/TracecatHQ/tracecat.git "$checkout"
    fi
    test "$(git -C "$checkout" describe --tags --exact-match)" = "$version" || { echo "Cached Tracecat checkout does not match $version; remove .cache/tracecat to change versions." >&2; exit 2; }
    docker compose --project-directory "$checkout" --env-file "$checkout/.env.example" --env-file "{{ root }}/.env" -f "$checkout/docker-compose.yml" up -d

tracecat-down:
    #!/usr/bin/env bash
    checkout="{{ root }}/.cache/tracecat"
    test -f "$checkout/docker-compose.yml" || exit 0
    docker compose --project-directory "$checkout" --env-file "$checkout/.env.example" --env-file "{{ root }}/.env" -f "$checkout/docker-compose.yml" down

# Start a gym's target services. Tracecat must already be running.
up gym:
    @docker compose --project-directory "{{ root }}/{{ gym }}" --env-file "{{ root }}/.env" -p "gym-{{ gym }}" -f "{{ root }}/{{ gym }}/compose.yml" up -d

down gym:
    @docker compose --project-directory "{{ root }}/{{ gym }}" --env-file "{{ root }}/.env" -p "gym-{{ gym }}" -f "{{ root }}/{{ gym }}/compose.yml" down

plan gym:
    #!/usr/bin/env bash
    if [[ "{{ gym }}" = 003 ]]; then
      export TF_VAR_secret_values="$(jq -cn --arg token "$BUNKERWEB_API_TOKEN" '{gym_003_waf:{BUNKERWEB_API_TOKEN:$token}}')"
    fi
    if [[ "{{ gym }}" = 001 ]]; then
      export TF_VAR_mcp_credentials="$(jq -cn --arg authorization "$SPLUNK_MCP_AUTHORIZATION" '{"splunk-mcp":{Authorization:$authorization}}')"
    fi
    TF_VAR_candidate_model="$(jq -cn --arg provider "$CANDIDATE_MODEL_PROVIDER" --arg name "$CANDIDATE_MODEL_NAME" '{provider:$provider,name:$name}')" \
    TF_VAR_judge_model="$(jq -cn --arg provider "$JUDGE_MODEL_PROVIDER" --arg name "$JUDGE_MODEL_NAME" '{provider:$provider,name:$name}')" \
      terraform -chdir="{{ root }}/{{ gym }}/terraform" plan

apply gym:
    #!/usr/bin/env bash
    if [[ "{{ gym }}" = 003 ]]; then
      export TF_VAR_secret_values="$(jq -cn --arg token "$BUNKERWEB_API_TOKEN" '{gym_003_waf:{BUNKERWEB_API_TOKEN:$token}}')"
    fi
    if [[ "{{ gym }}" = 001 ]]; then
      export TF_VAR_mcp_credentials="$(jq -cn --arg authorization "$SPLUNK_MCP_AUTHORIZATION" '{"splunk-mcp":{Authorization:$authorization}}')"
    fi
    TF_VAR_candidate_model="$(jq -cn --arg provider "$CANDIDATE_MODEL_PROVIDER" --arg name "$CANDIDATE_MODEL_NAME" '{provider:$provider,name:$name}')" \
    TF_VAR_judge_model="$(jq -cn --arg provider "$JUDGE_MODEL_PROVIDER" --arg name "$JUDGE_MODEL_NAME" '{provider:$provider,name:$name}')" \
      terraform -chdir="{{ root }}/{{ gym }}/terraform" apply

# Trigger Candidate Run asynchronously. Optional: CASE_IDS=a,b REPETITIONS=2.
run gym CASE_IDS="" REPETITIONS="1":
    #!/usr/bin/env bash
    workspace_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -raw workspace_id)"
    workflow_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -json workflow_ids | jq -r .candidate_run)"
    case_ids_value="{{ CASE_IDS }}"
    case_ids_value="${case_ids_value#CASE_IDS=}"
    repetitions_value="{{ REPETITIONS }}"
    repetitions_value="${repetitions_value#REPETITIONS=}"
    case_ids="$(jq -cn --arg value "$case_ids_value" '$value | if length == 0 then [] else split(",") end')"
    payload="$(jq -cn --arg workflow_id "$workflow_id" --argjson case_ids "$case_ids" --argjson repetitions "$repetitions_value" '{workflow_id:$workflow_id,inputs:{case_ids:$case_ids,repetitions:$repetitions}}')"
    response="$(curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" -H 'Content-Type: application/json' -d "$payload" "$TRACECAT_API_URL/workspaces/$workspace_id/workflow-executions")"
    echo "$response" | jq '{evaluation_run_id:.wf_exec_id}'

# Trigger Judge Run asynchronously for one Evaluation Run.
judge gym RUN_ID:
    #!/usr/bin/env bash
    workspace_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -raw workspace_id)"
    workflow_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -json workflow_ids | jq -r .judge_run)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    payload="$(jq -cn --arg workflow_id "$workflow_id" --arg run_id "$run_id" '{workflow_id:$workflow_id,inputs:{evaluation_run_id:$run_id}}')"
    response="$(curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" -H 'Content-Type: application/json' -d "$payload" "$TRACECAT_API_URL/workspaces/$workspace_id/workflow-executions")"
    echo "$response" | jq --arg run_id "$run_id" '{evaluation_run_id:$run_id,judge_run_execution_id:.wf_exec_id}'

status gym RUN_ID:
    #!/usr/bin/env bash
    workspace_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -raw workspace_id)"
    table_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -json table_ids | jq -r .evaluation_runs)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    curl -fsS -H "Authorization: Bearer $TRACECAT_API_KEY" "$TRACECAT_API_URL/workspaces/$workspace_id/tables/$table_id/rows?limit=1000" | jq --arg run_id "$run_id" '.items[] | select(.evaluation_run_id == $run_id)'

# Export criterion rows to NNN/results/<run-id>/scores.csv.
export gym RUN_ID:
    #!/usr/bin/env bash
    workspace_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -raw workspace_id)"
    table_id="$(terraform -chdir="{{ root }}/{{ gym }}/terraform" output -json table_ids | jq -r .evaluation_scores)"
    run_id="{{ RUN_ID }}"
    run_id="${run_id#RUN_ID=}"
    destination="{{ root }}/{{ gym }}/results/$run_id/scores.csv"
    rows_file="$(mktemp)"
    trap 'rm -f "$rows_file"' EXIT
    cursor=""
    while true; do
      query=(--get --data-urlencode "limit=1000")
      if [[ -n "$cursor" ]]; then
        query+=(--data-urlencode "cursor=$cursor")
      fi
      response="$(curl -fsS "${query[@]}" -H "Authorization: Bearer $TRACECAT_API_KEY" "$TRACECAT_API_URL/workspaces/$workspace_id/tables/$table_id/rows")"
      jq -c '.items[]' <<<"$response" >> "$rows_file"
      [[ "$(jq -r '.has_more' <<<"$response")" = true ]] || break
      cursor="$(jq -er '.next_cursor' <<<"$response")"
    done
    mkdir -p "$(dirname "$destination")"
    jq -sr --arg run_id "$run_id" '
      ["schema_version","gym_id","evaluation_run_id","trial_id","case_id","trial_number","candidate_session_id","judge_run_execution_id","judge_session_id","rubric_id","rubric_version","criterion_id","criterion_weight","criterion_result","criterion_points","criterion_hard_gate","trial_hard_failed","trial_score","reason","evidence_refs","candidate_completed_at","judged_at"],
      ((map(select(.evaluation_run_id == $run_id)) | sort_by(.case_id, .trial_number, .criterion_id))[] | [.schema_version,.gym_id,.evaluation_run_id,.trial_id,.case_id,.trial_number,.candidate_session_id,.judge_run_execution_id,.judge_session_id,.rubric_id,.rubric_version,.criterion_id,.criterion_weight,.criterion_result,.criterion_points,.criterion_hard_gate,.trial_hard_failed,.trial_score,.reason,(.evidence_refs|tojson),.candidate_completed_at,.judged_at]) | @csv' "$rows_file" > "$destination"
    echo "$destination"

check:
    #!/usr/bin/env bash
    for gym in 001 002 003; do
      jq -e . "{{ root }}/$gym/tracecat/tracecat.json" >/dev/null
      jq -e . "{{ root }}/$gym/evals/rubric.json" >/dev/null
      jq -cs --slurpfile rubric "{{ root }}/$gym/evals/rubric.json" '
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
      ' "{{ root }}/$gym/evals/cases.ndjson" >/dev/null
    done
    test "$(wc -l < "{{ root }}/001/evals/cases.ndjson" | tr -d ' ')" = 1
    test "$(wc -l < "{{ root }}/002/evals/cases.ndjson" | tr -d ' ')" = 20
    test "$(wc -l < "{{ root }}/003/evals/cases.ndjson" | tr -d ' ')" = 1
    ruby -e 'require "yaml"; ARGV.each { |path| YAML.load_file(path) }' "{{ root }}/terraform/modules/gym/workflows/candidate-run.yml" "{{ root }}/terraform/modules/gym/workflows/judge-run.yml" "{{ root }}/003/tracecat/workflows/validate-firewall-rule.yml"
    terraform fmt -check -recursive "{{ root }}"
    cd "{{ root }}/terraform-provider-tracecat"
    GOCACHE="{{ root }}/.cache/go-build" go test ./...
