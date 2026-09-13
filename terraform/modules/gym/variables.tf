variable "gym_id" {
  type = string
}

variable "config_dir" {
  type = string
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

variable "secret_values" {
  type      = map(map(string))
  sensitive = true
  ephemeral = true
  default   = {}
}

variable "mcp_credentials" {
  type      = map(map(string))
  sensitive = true
  ephemeral = true
  default   = {}
}
