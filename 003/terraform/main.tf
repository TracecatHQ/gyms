terraform {
  required_version = ">= 1.11.0"
  required_providers {
    tracecat = {
      source  = "tracecathq/tracecat"
      version = "0.1.0"
    }
  }
}

provider "tracecat" {}

variable "secret_values" {
  type      = map(map(string))
  sensitive = true
  ephemeral = true
}

variable "candidate_model" {
  type = object({ provider = string, name = string })
  default = {
    provider = "openai"
    name     = "gpt-5.2"
  }
}

variable "judge_model" {
  type = object({ provider = string, name = string })
  default = {
    provider = "openai"
    name     = "gpt-5.2"
  }
}

module "lab" {
  source          = "../../terraform/modules/lab"
  lab_id          = "003"
  config_dir      = "${path.module}/../tracecat"
  secret_values   = var.secret_values
  candidate_model = var.candidate_model
  judge_model     = var.judge_model
}

output "workspace_id" { value = module.lab.workspace_id }
output "workflow_ids" { value = module.lab.workflow_ids }
output "table_ids" { value = module.lab.table_ids }
