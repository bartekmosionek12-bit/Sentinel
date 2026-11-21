# Polityka tokenu kill switcha (API): wyłącznie hurtowe odwołanie tokenów, które `mcp-scanner`
# dostał z logowania AppRole. Nic więcej: bez podpisu certyfikatów, bez odczytu sekretów.
# Kill switch loguje się przez osobny punkt montowania `auth/killswitch`, więc odwołanie
# prefiksu `auth/approle/login` nie dotyka jego własnego tokenu.
path "sys/leases/revoke-prefix/auth/approle/login" {
  capabilities = ["update", "sudo"]
}
