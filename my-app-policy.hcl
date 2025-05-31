path "auth/kubernetes/login" {
    capabilities = ["create", "read"]
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