path "auth/kubernetes/login" {
    capabilities = ["create", "read"]
}
path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list", "delete"]
}
path "transit/encrypt/aes256-key" {
  capabilities = ["update"]
}
path "transit/decrypt/aes256-key" {
  capabilities = ["update"]
}
path "transit/keys/aes256-key" {
  capabilities = ["read"]
}
path "transit/keys/aes256-key/rotate" {
  capabilities = ["update"]
}
