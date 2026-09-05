// Vault agent configuration for the nightly billing sync.
// Runbook: authenticate the job with the batch token issued for it,
//   vault login {{VAULTBATCH_150_930}}

pid_file = "/run/vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/vault/role-id"
      secret_id_file_path = "/etc/vault/secret-id"
    }
  }
}

storage "postgresql" {
  connection_url = "postgres://vault@db.internal:5432/vault"
  password = "{{PWL_16_931}}"
}

template {
  destination = "/etc/billing/env"
  contents = "PGPASSWORD={{ with secret \"kv/billing\" }}{{ .Data.password }}{{ end }}"
}
