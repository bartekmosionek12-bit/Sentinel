#!/usr/bin/env bash
# Syntetyczne laboratorium do testu skali discovery (tylko lokalnie, w osobnej przestrzeni
# nazw sieci; żaden pakiet nie wychodzi poza maszynę). Zakres 10.200.0.0/18 = 16 384 adresy,
# z czego LIVE hostów odpowiada naprawdę, a reszta pakietów ginie w interfejsie dummy
# (realistyczne timeouty, jak w sieci z pustymi adresami). Wymaga roota oraz ip i nmap.
#   sudo scripts/perf_lab.sh up 48 && sudo ip netns exec asi-lab <polecenie> && sudo scripts/perf_lab.sh down
set -euo pipefail
NS=asi-lab
case "${1:-}" in
  up)
    LIVE=${2:-48}
    # Dwie przestrzenie nazw połączone parą veth: skaner (asi-lab) i „sieć” (asi-far).
    # asi-far odpowiada tylko z adresów żywych hostów; resztę pakietów po cichu porzuca
    # (brak przekazywania), więc nmap czeka na timeouty jak w prawdziwej, rzadkiej sieci.
    ip netns add "$NS"; ip netns add asi-far
    ip link add va netns "$NS" type veth peer name vb netns asi-far
    ip -n "$NS" link set lo up; ip -n asi-far link set lo up
    ip -n "$NS" addr add 192.168.77.1/30 dev va; ip -n asi-far addr add 192.168.77.2/30 dev vb
    ip -n "$NS" link set va up; ip -n asi-far link set vb up
    ip -n "$NS" route add 10.200.0.0/18 via 192.168.77.2
    : > /tmp/asi-lab-hosts.txt
    for i in $(seq 1 "$LIVE"); do
      addr="10.200.$((i * 5 % 64)).$((i * 37 % 250 + 2))"
      ip -n asi-far addr add "$addr/32" dev lo
      echo "$addr" >> /tmp/asi-lab-hosts.txt
    done
    ip netns exec asi-far python3 "$(dirname "$0")/perf_lab_services.py" /tmp/asi-lab-hosts.txt &
    echo $! > /tmp/asi-lab-services.pid
    echo "Lab gotowe: $(wc -l < /tmp/asi-lab-hosts.txt) żywych hostów w 10.200.0.0/18"
    ;;
  down)
    kill "$(cat /tmp/asi-lab-services.pid 2>/dev/null)" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip netns del asi-far 2>/dev/null || true
    ;;
  *) echo "użycie: $0 up [liczba_hostów] | down" >&2; exit 2 ;;
esac
