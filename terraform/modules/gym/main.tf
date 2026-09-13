terraform {
  required_version = ">= 1.11.0"

  required_providers {
    tracecat = {
      source  = "tracecathq/tracecat"
      version = "0.1.0"
    }
  }
}

locals {
  manifest = jsondecode(file("${var.config_dir}/tracecat.json"))
  rubric   = jsondecode(file("${var.config_dir}/../evals/rubric.json"))

  case_lines = [
    for line in split("\n", trimspace(file("${var.config_dir}/../evals/cases.ndjson"))) : line
    if trimspace(line) != ""
  ]
  case_records = [for line in local.case_lines : jsondecode(line)]
  cases        = { for record in local.case_records : record.case_id => record }

  judge_output_type = {
    type                 = "object"
    additionalProperties = false
    required             = ["evaluation_error", "criteria"]
    properties = {
      evaluation_error = { type = ["string", "null"] }
      criteria = {
        type     = "array"
        minItems = length(local.rubric.criteria)
        maxItems = length(local.rubric.criteria)
        prefixItems = [
          for criterion in local.rubric.criteria : {
            type                 = "object"
            additionalProperties = false
            required             = ["criterion_id", "result", "reason", "evidence_refs"]
            properties = {
              criterion_id = { type = "string", enum = [criterion.criterion_id] }
              result       = { type = "string", enum = ["met", "missed"] }
              reason       = { type = "string" }
              evidence_refs = {
                type  = "array"
                items = { type = "string" }
              }
            }
          }
        ]
        items = false
      }
    }
  }

  presets = { for preset in local.manifest.agent_presets : preset.slug => preset }
  standard_workflows = {
    candidate_run = { alias = "candidate_run", file = "candidate-run.yml", path = "${path.module}/workflows/candidate-run.yml" }
    judge_run     = { alias = "judge_run", file = "judge-run.yml", path = "${path.module}/workflows/judge-run.yml" }
  }
  gym_workflows = {
    for workflow in try(local.manifest.workflows, []) : workflow.alias => merge(workflow, { path = "${var.config_dir}/${workflow.file}" })
  }
  workflows    = merge(local.standard_workflows, local.gym_workflows)
  integrations = { for integration in try(local.manifest.mcp_integrations, []) : integration.catalog_slug => integration }
  secrets      = { for secret in try(local.manifest.secrets, []) : secret.name => secret }

  table_columns = {
    case_templates = [
      { name = "schema_version", type = "INTEGER", nullable = false },
      { name = "gym_id", type = "TEXT", nullable = false },
      { name = "case_id", type = "TEXT", nullable = false, is_index = true },
      { name = "case", type = "JSONB", nullable = false },
      { name = "oracle", type = "JSONB", nullable = false },
      { name = "rubric", type = "JSONB", nullable = false },
      { name = "rubric_id", type = "TEXT", nullable = false },
      { name = "rubric_version", type = "INTEGER", nullable = false },
      { name = "enabled", type = "BOOLEAN", nullable = false }
    ]
    evaluation_scores = [
      { name = "score_key", type = "TEXT", nullable = false, is_index = true },
      { name = "schema_version", type = "INTEGER", nullable = false },
      { name = "gym_id", type = "TEXT", nullable = false },
      { name = "evaluation_run_id", type = "TEXT", nullable = false },
      { name = "trial_id", type = "TEXT", nullable = false },
      { name = "case_id", type = "TEXT", nullable = false },
      { name = "trial_number", type = "INTEGER", nullable = false },
      { name = "candidate_session_id", type = "TEXT", nullable = false },
      { name = "judge_run_execution_id", type = "TEXT", nullable = false },
      { name = "judge_session_id", type = "TEXT", nullable = false },
      { name = "rubric_id", type = "TEXT", nullable = false },
      { name = "rubric_version", type = "INTEGER", nullable = false },
      { name = "criterion_id", type = "TEXT", nullable = false },
      { name = "criterion_weight", type = "NUMERIC", nullable = false },
      { name = "criterion_result", type = "TEXT", nullable = false },
      { name = "criterion_points", type = "NUMERIC", nullable = false },
      { name = "criterion_hard_gate", type = "BOOLEAN", nullable = false },
      { name = "trial_hard_failed", type = "BOOLEAN", nullable = false },
      { name = "trial_score", type = "NUMERIC", nullable = false },
      { name = "reason", type = "TEXT", nullable = false },
      { name = "evidence_refs", type = "JSONB", nullable = false },
      { name = "candidate_completed_at", type = "TIMESTAMPTZ", nullable = false },
      { name = "judged_at", type = "TIMESTAMPTZ", nullable = false }
    ]
  }
}

resource "tracecat_workspace" "gym" {
  name = local.manifest.workspace_name
}

resource "tracecat_table" "platform" {
  for_each = local.table_columns

  workspace_id = tracecat_workspace.gym.id
  name         = each.key
  columns_json = jsonencode(each.value)
}

resource "tracecat_table_row" "case_template" {
  for_each = local.cases

  workspace_id    = tracecat_workspace.gym.id
  table_id        = tracecat_table.platform["case_templates"].id
  identity_column = "case_id"
  identity_value  = each.key
  upsert          = true
  data_json = jsonencode({
    schema_version = each.value.schema_version
    gym_id         = var.gym_id
    case_id        = each.key
    case           = each.value.case
    oracle         = each.value.oracle
    rubric         = local.rubric
    rubric_id      = local.rubric.rubric_id
    rubric_version = local.rubric.rubric_version
    enabled        = try(each.value.enabled, true)
  })
}

resource "tracecat_agent_preset" "preset" {
  for_each = local.presets

  workspace_id = tracecat_workspace.gym.id
  config_json = jsonencode(merge(
    { for key, value in each.value : key => value if !contains(["instructions_file", "model_role", "mcp_catalog_slugs"], key) },
    {
      instructions     = file("${var.config_dir}/${each.value.instructions_file}")
      model_provider   = each.value.model_role == "candidate" ? var.candidate_model.provider : var.judge_model.provider
      model_name       = each.value.model_role == "candidate" ? var.candidate_model.name : var.judge_model.name
      catalog_id       = null
      mcp_integrations = [for slug in try(each.value.mcp_catalog_slugs, []) : tracecat_mcp_integration.integration[slug].id]
      output_type      = each.value.model_role == "judge" ? local.judge_output_type : null
    }
  ))
}

resource "tracecat_workflow" "workflow" {
  for_each = local.workflows

  workspace_id = tracecat_workspace.gym.id
  filename     = each.value.file
  alias        = each.key
  yaml         = file(each.value.path)

  depends_on = [
    tracecat_agent_preset.preset,
    tracecat_table_row.case_template,
    tracecat_mcp_integration.integration,
    tracecat_secret.secret
  ]
}

resource "tracecat_mcp_integration" "integration" {
  for_each = local.integrations

  workspace_id           = tracecat_workspace.gym.id
  catalog_slug           = each.value.catalog_slug
  connection_option_id   = try(each.value.connection_option_id, null)
  name                   = try(each.value.name, null)
  description            = try(each.value.description, null)
  server_uri             = try(each.value.server_uri, null)
  auth_type              = try(each.value.auth_type, "CUSTOM")
  timeout                = try(each.value.timeout, 120)
  custom_headers_wo_json = contains(keys(var.mcp_credentials), each.key) ? jsonencode(var.mcp_credentials[each.key]) : null
  credentials_wo_version = try(each.value.credentials_version, 0)
}

resource "tracecat_secret" "secret" {
  for_each = local.secrets

  workspace_id    = tracecat_workspace.gym.id
  name            = each.key
  description     = try(each.value.description, null)
  environment     = try(each.value.environment, "default")
  keys_wo_json    = jsonencode(var.secret_values[each.key])
  keys_wo_version = each.value.version
}
