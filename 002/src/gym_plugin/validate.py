"""Repository integrity plus read-only checks against the running Gym 002 stack."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess

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

    with (config.ROOT / "benchmark/scenario/alerts.csv").open(newline="") as stream:
        alerts = list(csv.DictReader(stream))
    require(
        len(alerts) == 34 and len({row["alert_id"] for row in alerts}) == 34,
        "alert queue must contain 34 unique cases",
    )
    with (config.ROOT / "benchmark/evals/alert_outcomes.csv").open(
        newline=""
    ) as stream:
        outcomes = list(csv.DictReader(stream))
    require(
        {row["alert_id"] for row in outcomes} == {row["alert_id"] for row in alerts},
        "hidden outcomes do not exactly match the alert queue",
    )
    evaluation = evaluate.load_configuration()
    contracts = evaluate.load_contracts(evaluation)
    require(
        len(reconcile.source_cases()) == 34, "case projection does not contain 34 rows"
    )
    require(
        len(contracts) == 34
        and {row["alert_id"] for row in contracts if row["required_enrichments"]}
        == evaluate.REQUIRED_ENRICHMENT_CASES,
        "evaluation contracts or enrichment case set drifted",
    )

    investigator = json.loads(
        (config.ROOT / "benchmark/agent/investigator-preset.json").read_text()
    )
    actions = set(investigator["actions"])
    expected_actions = {
        "core.cases.add_case_tag",
        "core.cases.create_comment",
        "core.cases.get_case",
        "core.cases.search_cases",
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
    require(
        not (config.ROOT / "evals.json").exists(), "legacy evals.json must be removed"
    )
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
        == {("127.0.0.1", 28080)},
        "port exposure must be only localhost:28080",
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

    env = config.parse_env()
    from gymctl.http import Client

    with Client(base_url=env["PUBLIC_API_URL"], timeout=120) as client:
        reconcile.status(
            client,
            env["TRACEcat_TENANT_EMAIL"],
            env["TRACEcat_TENANT_PASSWORD"],
        )
    print("[gym-002] Repository and live integration checks passed.")
