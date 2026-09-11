"""Repository integrity plus read-only checks against the running Gym 002 stack."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys

from . import config, evaluate, reconcile
from .dataset import validate_archive


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def validate() -> None:
    lock = config.load_lock()
    platform = config.load_platform_lock()
    require(lock["schema_version"] == 2, "gym.lock.json schema must be 2")
    require(
        lock["gym"]["id"] == "002" and lock["gym"]["compose_project"] == config.PROJECT,
        "gym identity drifted",
    )
    validate_archive()
    require(platform["schema_version"] == 1, "platform.lock.json schema must be 1")
    require(
        hashlib.sha256(
            (config.REPO_ROOT / "upstream/tracecat/docker-compose.yml").read_bytes()
        ).hexdigest()
        == platform["tracecat"]["compose_sha256"],
        "shared Tracecat Compose checksum mismatch",
    )
    require(
        hashlib.sha256(
            (config.REPO_ROOT / "upstream/tracecat/Caddyfile").read_bytes()
        ).hexdigest()
        == platform["tracecat"]["caddyfile_sha256"],
        "shared Caddyfile checksum mismatch",
    )

    audit = subprocess.run(
        [sys.executable, str(config.ROOT / "tools/update_dataset.py"), "--check"],
        cwd=config.ROOT,
        text=True,
        capture_output=True,
    )
    require(
        audit.returncode == 0,
        f"BOTSv3 corpus contract audit failed: {audit.stdout}{audit.stderr}",
    )
    evaluation = evaluate.load_configuration()
    contracts = evaluate.load_contracts(evaluation)
    require(
        len(reconcile.source_cases()) == 20, "case projection does not contain 20 rows"
    )
    require(
        len(contracts) == 20
        and sum(bool(row["required_enrichments"]) for row in contracts) == 5
        and all(
            row["required_enrichments"] == ["urlscan", "virustotal"]
            and len(row["enrichment_targets"]) == 1
            for row in contracts
            if row["required_enrichments"]
        ),
        "evaluation contracts or enrichment requirements drifted",
    )

    investigator = json.loads(
        (config.ROOT / "benchmark/agent/investigator-preset.json").read_text()
    )
    actions = set(investigator["actions"])
    expected_actions = {
        "core.cases.add_case_tag",
        "core.cases.assign_user_by_email",
        "core.cases.create_comment",
        "core.cases.get_case",
        "core.cases.update_case",
        "core.duckdb.execute_sql",
        "tools.urlscan.get_result",
        "tools.urlscan.get_screenshot",
        "tools.urlscan.search_scans",
        "tools.virustotal.lookup_domain",
        "tools.virustotal.lookup_file_hash",
        "tools.virustotal.lookup_ip_address",
        "tools.virustotal.lookup_url",
    }
    require(
        "tools.urlscan.lookup_url" not in actions,
        "URLscan submission must not be enabled",
    )
    require(
        actions == expected_actions,
        "investigator action allowlist has drifted",
    )
    grader = json.loads(
        (config.ROOT / "benchmark/evals/grader-preset.json").read_text()
    )
    require(
        grader["actions"] == []
        and grader["mcp_integrations"] == []
        and grader.get("skills", []) == [],
        "grader manifest must remain tool-free",
    )
    from gymctl import tables as table_lib, workflows as workflow_lib

    workflow_paths = sorted(reconcile.WORKFLOWS_DIR.glob("*.json"))
    require(
        len(workflow_paths) == reconcile.EXPECTED_WORKFLOWS,
        f"expected {reconcile.EXPECTED_WORKFLOWS} managed workflow manifests",
    )
    managed_workflows = {
        (manifest := workflow_lib.load_manifest(path))["alias"]: manifest
        for path in workflow_paths
    }
    for alias, manifest in managed_workflows.items():
        unknown = sorted(
            workflow_lib.subflow_aliases(manifest) - set(managed_workflows)
        )
        require(not unknown, f"workflow {alias} invokes unmanaged subflows: {unknown}")
    workflow = workflow_lib.load_manifest(reconcile.INVESTIGATE_WORKFLOW)
    require(
        workflow["alias"] == evaluation["investigator_workflow"]["alias"],
        "managed workflow alias does not match the evaluation configuration",
    )
    expects = set((workflow["definition"].get("entrypoint") or {}).get("expects") or {})
    require(
        {"case_id", "session_id"} <= expects,
        "managed workflow must accept case_id and session_id trigger inputs",
    )
    require(
        (workflow.get("case_trigger") or {}).get("status") != "online",
        "managed workflow case trigger must not be online; it would race the evaluator",
    )
    manifests = [
        table_lib.load_manifest(path)
        for path in sorted(reconcile.TABLES_DIR.glob("*.json"))
    ]
    require(
        len(manifests) == reconcile.EXPECTED_TABLES,
        f"expected {reconcile.EXPECTED_TABLES} managed table manifests",
    )
    require(
        not (config.ROOT / "evals.json").exists(), "legacy evals.json must be removed"
    )
    for legacy in (
        "benchmark/scenario/alerts.csv",
        "benchmark/evals/alert_outcomes.csv",
        "benchmark/evals/answers.csv",
    ):
        require(not (config.ROOT / legacy).exists(), f"legacy file remains: {legacy}")
    require(
        not (config.ROOT / "skills").exists(), "skills must live under benchmark/agent"
    )
    require(
        not (config.ROOT / "data").exists(), "benchmark data must not live at gym root"
    )
    require(not (config.ROOT / "tests").exists(), "unit tests are not part of the gym")

    dockerfile = (config.ROOT / "images/control/Dockerfile").read_text()
    require(
        "assets" not in dockerfile and ".zip" not in dockerfile,
        "dataset must not be copied into an image",
    )
    merged = subprocess.run(
        config.compose_args(
            "--profile",
            "bootstrap",
            "--profile",
            "evaluation",
            "config",
            "--format",
            "json",
        ),
        cwd=config.ROOT,
        env=config.compose_environment(),
        text=True,
        capture_output=True,
    )
    require(merged.returncode == 0, f"Compose config failed: {merged.stderr}")
    compose = json.loads(merged.stdout)
    services = compose["services"]
    require(
        services["eval-runner"].get("user") == f"{os.getuid()}:{os.getgid()}"
        and services["eval-runner"].get("environment", {}).get("HOME") == "/tmp",
        "eval-runner must write host artifacts as the invoking UID/GID",
    )
    require(
        all("container_name" not in service for service in services.values()),
        "merged Compose contains a fixed container name",
    )
    expected_images = {
        "dataset-seed": config.local_image(),
        "tracecat-seed": config.local_image(),
        "gym-reconciler": config.local_image(),
        "eval-runner": config.local_image(),
    }
    require(
        all(
            services[name]["image"] == image for name, image in expected_images.items()
        ),
        "merged Compose does not use the deterministic control image",
    )
    for service in (
        "api",
        "worker",
        "executor",
        "agent-worker",
        "litellm",
        "agent-executor",
        "mcp",
        "migrations",
    ):
        environment = services[service].get("environment", {})
        require(
            environment.get("ENTERPRISE_EDITION") == "true"
            and environment.get("TRACECAT__EE_MULTI_TENANT") == "true",
            f"enterprise mode is not enabled for {service}",
        )
    ports = [
        binding for service in services.values() for binding in service.get("ports", [])
    ]
    require(
        {
            (str(binding.get("host_ip")), int(binding.get("published")))
            for binding in ports
        }
        == {("127.0.0.1", config.DEFINITION.host_port)},
        f"port exposure must be only localhost:{config.DEFINITION.host_port}",
    )
    binds = {
        (str(mount.get("source")), str(mount.get("target")))
        for service in services.values()
        for mount in service.get("volumes", [])
        if mount.get("type") == "bind"
    }
    require(
        binds
        == {
            (
                str(
                    (config.ROOT / "assets/botsv3-20260904T130332Z-1-001.zip").resolve()
                ),
                "/run/gym-data/botsv3.zip",
            ),
            (str((config.ROOT / "eval-results").resolve()), "/opt/gym/eval-results"),
        },
        f"unexpected host bind mounts: {sorted(binds)}",
    )
    mount = "assets/botsv3-20260904T130332Z-1-001.zip:/run/gym-data/botsv3.zip:ro"
    require(
        (config.ROOT / "compose.override.yml").read_text().count(mount) == 1
        and "/run/gym-data/botsv3.zip" in merged.stdout,
        "dataset must have exactly one read-only runtime mount",
    )
    require(
        lock["images"]["local"]["control"]["input_sha256"] == config.image_input_hash(),
        "locked control-image input hash is stale",
    )

    for service in ("api", "litellm", "postgres_db", "temporal", "minio", "redis"):
        rows = (
            config.run_compose("ps", "--quiet", service, capture=True)
            .stdout.strip()
            .splitlines()
        )
        require(len(rows) == 1, f"running stack is missing service {service}")
        state = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                rows[0],
            ],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        require(
            state == "running healthy", f"service {service} is not healthy: {state}"
        )
    seed = config.run_compose(
        "--profile", "bootstrap", "ps", "--all", "--quiet", "dataset-seed", capture=True
    ).stdout.strip()
    require(bool(seed), "dataset seed container is missing")
    seed_state = subprocess.run(
        [
            "docker",
            "inspect",
            "--format",
            "{{.State.Status}} {{.State.ExitCode}}",
            seed,
        ],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    require(
        seed_state == "exited 0",
        f"dataset seed did not complete successfully: {seed_state}",
    )
    seed_image = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", seed],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    require(
        seed_image == config.local_image("control"),
        f"dataset seed used stale control image: {seed_image}",
    )
    seed_logs = subprocess.run(
        ["docker", "logs", seed],
        check=True,
        text=True,
        capture_output=True,
    ).stdout
    require(
        "489968 records" in seed_logs
        and "event_ref=sha256-object-line-v1" in seed_logs,
        "seeded MinIO objects were not verified with stable event references",
    )

    env = config.parse_env()
    from gymctl.http import Client

    with Client(
        base_url=env["PUBLIC_API_URL"], timeout=120, follow_redirects=True
    ) as client:
        reconcile.status(
            client,
            env["TRACEcat_TENANT_EMAIL"],
            env["TRACEcat_TENANT_PASSWORD"],
        )
    print("[gym-002] Repository and live integration checks passed.")
