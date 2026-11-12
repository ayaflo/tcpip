#!/bin/bash
# setup_unbound.sh - Trich xuat Trust Anchor va khoi tao cau hinh Unbound
set -e

echo "[*] 1. Trich xuat DNSKEY (KSK - 257) tu dns-auth de lam Trust Anchor..."

FOUND=0
for i in {1..10}; do
    ip netns exec client dig @10.0.0.2 lab.test DNSKEY +noall +answer > /tmp/lab.dnskey 2>/dev/null || true
    if grep -q -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey 2>/dev/null; then
        echo "[+] Tim thay DNSKEY 257 sau ${i} giay!"
        FOUND=1
        break
    fi
    echo "    [-] Dang doi BIND9 khoi dong va ky zone... (lan ${i}/10)"
    sleep 1
done

if [ $FOUND -eq 0 ]; then
    echo "[-] LOI: Khong the trich xuat DNSKEY 257 tu dns-auth (10.0.0.2)!"
    echo "    Nguyen nhan: BIND9 tren dns-auth chua chay hoac da bi thoat dot ngot."
    echo "    Hay kiem tra: ip netns exec dns-auth named -c /tmp/named-auth.conf -g"
    exit 1
fi

grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey > /tmp/trust-anchor.key
mkdir -p /etc/unbound
cp /tmp/trust-anchor.key /etc/unbound/trust-anchor.key 2>/dev/null || true

echo "[+] Trust Anchor trich xuat thanh cong:"
cat /tmp/trust-anchor.key

echo ""
echo "[*] 2. Tao file cau hinh Unbound Resolver: /tmp/unbound.conf..."
cat <<'EOF' > /tmp/unbound.conf
server:
    verbosity: 1
    interface: 10.0.0.3
    port: 53
    username: ""
    chroot: ""
    use-syslog: no
    pidfile: ""
    directory: "/etc/unbound"
    do-ip6: no
    access-control: 10.0.0.0/24 allow
    module-config: "validator iterator"
    harden-dnssec-stripped: yes
    val-permissive-mode: no
    trust-anchor-file: "/tmp/trust-anchor.key"
    domain-insecure: "."
    local-zone: "test." nodefault
    local-zone: "lab.test." transparent

stub-zone:
    name: "lab.test"
    stub-addr: 10.0.0.2
EOF
cp /tmp/unbound.conf /etc/unbound/unbound.conf 2>/dev/null || true

echo "[+] Da tao xong /tmp/unbound.conf!"
