# OpenBao dla Sentinel ASI: magazyn zintegrowany (raft, jeden węzeł) w wolumenie, nasłuch
# tylko w sieci `vault`. TLS wewnątrz sieci Dockera jest wyłączony (sieć wewnętrzna, bez
# portów na hoście); TLS całego stosu dochodzi w Etapie 9 (profil `tls`).
storage "raft" {
  path    = "/openbao/file"
  node_id = "sentinel-bao-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://openbao:8200"
cluster_addr = "http://openbao:8201"
ui           = false
