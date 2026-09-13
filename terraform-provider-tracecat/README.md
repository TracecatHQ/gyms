# Tracecat Terraform provider

This repository-local provider provisions the Tracecat resources used by the
gyms through the public REST API. It intentionally has a small surface:
workspaces, native workflow YAML, agent presets, tables and rows, Case metadata,
catalog MCP integrations, secrets, and model lookup.

Set `TRACECAT_API_URL` and `TRACECAT_API_KEY`, then run `just init`. The root
Justfile builds and installs the provider under `.terraform.d/plugins` and
initializes Terraform from that local plugin directory, so no registry
publication is required.

`tracecat_secret.keys_wo_json` requires Terraform 1.11 or newer. Secret values are
sent to Tracecat but are not persisted in Terraform plan or state.
