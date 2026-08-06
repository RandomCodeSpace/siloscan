terraform {
  required_version = ">= 1.9.0"
}

provider "aws" {
  region = "eu-west-1"
  access_key = "{{AWSKEYID_0_200}}"
  secret_key = "{{AWSSECRET_0_201}}"
}

resource "kubernetes_secret" "billing" {
  data = {
    database_password = "{{PWA_24_202}}"
    api_token         = "{{B64_40_203}}"
    signing_secret    = "{{HEX_64_204}}"
    openai_api_key    = "{{OPENAI_0_205}}"
    gcp_api_key       = "{{GCPKEY_0_206}}"
    admin_password    = "{{PWP_20_207}}"
    database_url      = "postgres://tf:{{PWA_20_208}}@db.internal:5432/billing"
  }
}

resource "kubernetes_secret" "billing_from_vars" {
  data = {
    database_password = var.database_password
    api_token         = "${var.api_token}"
    signing_secret    = data.vault_generic_secret.billing.data["signing_secret"]
    admin_password    = "changeme"
    endpoint          = "https://billing.internal/api/v2"
    module_source     = "terraform-aws-modules/vpc/aws"
    state_lock_table  = "terraform-state-lock-billing-eu-west-1"
  }
}
