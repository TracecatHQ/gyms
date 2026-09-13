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

variable "mcp_credentials" {
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

module "gym" {
  source          = "../../terraform/modules/gym"
  gym_id          = "001"
  config_dir      = "${path.module}/../tracecat"
  mcp_credentials = var.mcp_credentials
  candidate_model = var.candidate_model
  judge_model     = var.judge_model
}

output "workspace_id" { value = module.gym.workspace_id }
output "workflow_ids" { value = module.gym.workflow_ids }
output "table_ids" { value = module.gym.table_ids }
