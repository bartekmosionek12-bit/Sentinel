# Polityka tokenu `mcp-scanner`: wyłącznie podpis certyfikatu SSH dla roli tylko do odczytu.
# Token żyje 15 minut i jest odwoływany po każdym kroku (revoke-self z polityki default).
path "ssh-client-signer/sign/sentinel-scanner" {
  capabilities = ["update"]
}
