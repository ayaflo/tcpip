#!/bin/bash
# setup_unbound_real.sh - Trich xuat Trust Anchor va khoi tao Unbound cho 2 may that
set -e

SERVER_IP=${1:-"0.0.0.0"}

echo "=================================================================="
echo "[*] TRICH XUAT TRUST ANCHOR VA KHOI TAO UNBOUND (LISTEN: $SERVER_IP:53)"
echo "=================================================================="

FOUND=0
for i in {1..10}; do
    dig @127.0.0.1 -p 5353 lab.test DNSKEY +noall +answer > /tmp/lab.dnskey 2>/dev/null || true
    if grep -q -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey 2>/dev/null; then
        echo "[+] Tim thay DNSKEY 257 sau ${i} giay!"
        FOUND=1
        break
    fi
    echo "    [-] Dang doi BIND9 khoi dong va ky zone... (lan ${i}/10)"
    sleep 1
done

if [ $FOUND -eq 0 ]; then
    echo "[-] LOI: Khong the trich xuat DNSKEY 257 tu BIND9 (127.0.0.1:5353)!"
    echo "    Kiem tra lai: BIND9 da chay chua? (named -c /etc/bind/named-auth.conf -g &)"
    exit 1
fi

grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey > /etc/unbound/trust-anchor.key
cp /etc/unbound/trust-anchor.key /tmp/trust-anchor.key 2>/dev/null || true

echo "[+] Trust Anchor (KSK - 257) trich xuat thanh cong:"
cat /etc/unbound/trust-anchor.key

echo ""
echo "[*] Tao file cau hinh Unbound Resolver cho mang Wi-Fi: /etc/unbound/unbound.conf..."
cat <<EOF > /etc/unbound/unbound.conf
server:
    verbosity: 1
    interface: $SERVER_IP
    port: 53
    username: ""
    chroot: ""
    use-syslog: no
    pidfile: ""
    directory: "/etc/unbound"
    do-ip6: no
    access-control: 0.0.0.0/0 allow
    module-config: "validator iterator"
    harden-dnssec-stripped: yes
    val-permissive-mode: no
    trust-anchor-file: "/etc/unbound/trust-anchor.key"
    domain-insecure: "."
    local-zone: "test." nodefault
    local-zone: "lab.test." transparent

stub-zone:
    name: "lab.test"
    stub-addr: 127.0.0.1@5353
EOF
cp /etc/unbound/unbound.conf /tmp/unbound.conf 2>/dev/null || true

echo "[+] Da tao xong /etc/unbound/unbound.conf va /tmp/unbound.conf!"
