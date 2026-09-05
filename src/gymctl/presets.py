"""Shared Tracecat skill and agent-preset reconciliation."""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import tracecat
from .http import ClientLike


class PresetError(RuntimeError):
    pass


def _request(
    client: ClientLike,
    method: str,
    path: str,
    *,
    expected: tuple[int, ...] = (200,),
    **kwargs: Any,
) -> Any:
    try:
        return tracecat.request_json(client, method, path, expected=expected, **kwargs)
    except tracecat.TracecatError as exc:
        raise PresetError(str(exc)) from exc


def local_skill_files(directory: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "content_base64": base64.b64encode(path.read_bytes()).decode(),
                "content_type": mimetypes.guess_type(path.name)[0] or "text/plain",
            }
        )
    if not files or not any(item["path"] == "SKILL.md" for item in files):
        raise PresetError(f"skill {directory.name} has no SKILL.md")
    return files


def local_skill_hashes(directory: Path) -> dict[str, str]:
    return {
        path.relative_to(directory).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(item for item in directory.rglob("*") if item.is_file())
    }


def skill_matches(
    client: ClientLike,
    workspace_id: str,
    skill: dict[str, Any],
    directory: Path,
) -> bool:
    version_id = skill.get("current_version_id")
    if not version_id:
        return False
    version = _request(
        client,
        "GET",
        f"/workspaces/{workspace_id}/agent/skills/{skill['id']}/versions/{version_id}",
    )
    remote = {
        str(item.get("path")): str(item.get("sha256"))
        for item in version.get("files", [])
        if isinstance(item, dict)
    }
    return remote == local_skill_hashes(directory)


def reconcile_skills(
    client: ClientLike,
    workspace_id: str,
    skills_dir: Path,
    *,
    managed_preset_slugs: set[str],
    expected_count: int,
    logger: Callable[[str], None] | None = None,
) -> list[str]:
    base = f"/workspaces/{workspace_id}/agent/skills"
    payload = _request(client, "GET", base, params={"limit": 100})
    existing = tracecat.paginated_items(payload, "skill list")
    directories = sorted(path for path in skills_dir.iterdir() if path.is_dir())
    if len(directories) != expected_count:
        raise PresetError(
            f"expected {expected_count} local skills, found {len(directories)}"
        )
    skill_ids: list[str] = []
    detached = False
    for directory in directories:
        matches = [
            row
            for row in existing
            if row.get("name") == directory.name or row.get("slug") == directory.name
        ]
        if len(matches) > 1:
            raise PresetError(f"multiple workspace skills match {directory.name}")
        skill = matches[0] if matches else None
        if skill is not None and not skill_matches(
            client, workspace_id, skill, directory
        ):
            if not detached:
                preset_base = f"/workspaces/{workspace_id}/agent/presets"
                presets = _request(client, "GET", preset_base)
                for preset in presets if isinstance(presets, list) else []:
                    if (
                        isinstance(preset, dict)
                        and preset.get("slug") in managed_preset_slugs
                    ):
                        _request(
                            client,
                            "PATCH",
                            f"{preset_base}/{preset['id']}",
                            body={"skills": []},
                        )
                detached = True
            _request(client, "DELETE", f"{base}/{skill['id']}", expected=(204,))
            skill = None
            if logger:
                logger(f"replaced drifted skill {directory.name}")
        if skill is None:
            skill = _request(
                client,
                "POST",
                f"{base}:upload",
                body={"name": directory.name, "files": local_skill_files(directory)},
                expected=(201,),
            )
        if not skill.get("current_version_id"):
            _request(client, "POST", f"{base}/{skill['id']}/publish")
            skill = _request(client, "GET", f"{base}/{skill['id']}")
        if not skill_matches(client, workspace_id, skill, directory):
            raise PresetError(f"published skill {directory.name} does not match Git")
        skill_ids.append(str(skill["id"]))
    return skill_ids


def load_manifest(directory: Path, filename: str) -> tuple[dict[str, Any], str]:
    manifest = json.loads((directory / filename).read_text())
    prompt_file = manifest.get("prompt_file")
    if not isinstance(prompt_file, str) or not prompt_file:
        raise PresetError(f"{filename} is missing prompt_file")
    prompt_path = (directory / prompt_file).resolve()
    if prompt_path.parent != directory.resolve():
        raise PresetError(f"{filename} prompt must stay in {directory}")
    prompt = prompt_path.read_text().strip()
    if not prompt:
        raise PresetError(f"{filename} prompt is empty")
    return manifest, prompt


def workspace_model(
    client: ClientLike, workspace_id: str, provider: str, name: str
) -> dict[str, Any]:
    payload = _request(client, "GET", f"/workspaces/{workspace_id}/agent-models")
    rows = tracecat.paginated_items(payload, "workspace model list")
    matches = [
        row
        for row in rows
        if row.get("model_provider") == provider and row.get("model_name") == name
    ]
    if len(matches) != 1:
        raise PresetError(f"model {provider}/{name} is not uniquely available")
    status = _request(client, "GET", "/agent/providers/status")
    if not isinstance(status, dict) or status.get(provider) is not True:
        raise PresetError(
            f"credentials for model provider {provider!r} are unavailable"
        )
    model = matches[0]
    catalog_id = model.get("catalog_id") or model.get("id")
    if not isinstance(catalog_id, str) or not catalog_id:
        raise PresetError(f"model {provider}/{name} has no catalog id")
    return model


def preset_payload(
    manifest: dict[str, Any],
    prompt: str,
    model: dict[str, Any],
    skill_ids: list[str],
) -> dict[str, Any]:
    fields = (
        "name",
        "slug",
        "description",
        "actions",
        "namespaces",
        "tool_approvals",
        "mcp_integrations",
        "agents",
        "retries",
        "enable_thinking",
        "enable_internet_access",
    )
    missing = [field for field in fields if field not in manifest]
    if missing:
        raise PresetError(f"preset manifest is missing fields: {missing}")
    return {field: manifest[field] for field in fields} | {
        "instructions": prompt,
        "model_name": model["model_name"],
        "model_provider": model["model_provider"],
        "catalog_id": model.get("catalog_id") or model.get("id"),
        "skills": [{"skill_id": skill_id} for skill_id in skill_ids],
    }


def reconcile_preset(
    client: ClientLike,
    workspace_id: str,
    desired: dict[str, Any],
) -> dict[str, Any]:
    base = f"/workspaces/{workspace_id}/agent/presets"
    rows = _request(client, "GET", base)
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and (row.get("slug") == desired["slug"] or row.get("name") == desired["name"])
    ]
    if len(matches) > 1:
        raise PresetError(f"multiple presets match {desired['slug']}")
    if matches:
        _request(client, "PATCH", f"{base}/{matches[0]['id']}", body=desired)
    else:
        _request(client, "POST", base, body=desired, expected=(201,))
    return verify_preset(client, workspace_id, desired)


def verify_preset(
    client: ClientLike,
    workspace_id: str,
    desired: dict[str, Any],
) -> dict[str, Any]:
    """Return the uniquely matching preset after a read-only exact drift check."""

    base = f"/workspaces/{workspace_id}/agent/presets"
    rows = _request(client, "GET", base)
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and (row.get("slug") == desired["slug"] or row.get("name") == desired["name"])
    ]
    if len(matches) != 1:
        raise PresetError(
            f"preset {desired['slug']} is missing or ambiguous ({len(matches)} matches)"
        )
    actual = _request(client, "GET", f"{base}/{matches[0]['id']}")
    drift = [
        key for key in desired if key != "skills" and actual.get(key) != desired[key]
    ]
    actual_skill_ids = [
        str(row.get("skill_id"))
        for row in actual.get("skills", [])
        if isinstance(row, dict)
    ]
    if actual_skill_ids != [str(row["skill_id"]) for row in desired["skills"]]:
        drift.append("skills")
    if drift:
        raise PresetError(f"preset {desired['slug']} drifted fields: {drift}")
    return actual
