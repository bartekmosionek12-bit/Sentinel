#!/bin/sh
# Czeka na klucz CA z bao-init, publikuje własny klucz hosta do wspólnego known_hosts
# (mcp-scanner łączy się tylko z hostem o znanym kluczu) i uruchamia sshd.
set -eu
for _ in $(seq 1 120); do
  [ -s /ca/ca.pub ] && break
  sleep 1
done
cp /ca/ca.pub /etc/ssh/ca.pub
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
ADDRESS="${LAB_SSH_ADDRESS:-172.30.99.16}"
echo "$ADDRESS $(cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub)" > /known/known_hosts.tmp
mv /known/known_hosts.tmp /known/known_hosts
exec /usr/sbin/sshd -D -e
