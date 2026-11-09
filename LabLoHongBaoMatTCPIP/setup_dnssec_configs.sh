#!/bin/bash
# setup_dnssec_configs.sh - Tao cac file cau hinh va zone cho Lab 07 (DNSSEC)
set -e

echo "[*] 1. Xu ly bao ve AppArmor de BIND9 va Unbound khong bi chan quyen..."
if [ -d /etc/apparmor.d/disable ]; then
    ln -sf /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/ 2>/dev/null || true
    ln -sf /etc/apparmor.d/usr.sbin.unbound /etc/apparmor.d/disable/ 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
fi

echo "[*] 2. Tao thu muc va phan quyen 777 toan dien cho BIND9..."
mkdir -p /var/cache/bind /etc/bind /etc/unbound
chmod -R 777 /var/cache/bind
chmod 777 /etc/bind /etc/unbound
chown -R bind:bind /var/cache/bind /etc/bind 2>/dev/null || true
chmod -R 777 /var/cache/bind

echo "[*] 3. Tao file cau hinh Authoritative DNS server (CO DNSSEC): /tmp/named-auth.conf"
cat <<'EOF' > /tmp/named-auth.conf
options {
    directory "/var/cache/bind";
    listen-on port 53 { 10.0.0.2; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
};

zone "lab.test" {
    type primary;
    file "db.lab.test";
    dnssec-policy default;
    inline-signing yes;
};
EOF
chmod 777 /tmp/named-auth.conf
cp /tmp/named-auth.conf /etc/bind/named-auth.conf 2>/dev/null || true
chmod 777 /etc/bind/named-auth.conf 2>/dev/null || true

echo "[*] 4. Tao file zone hop le: /var/cache/bind/db.lab.test (www -> 10.0.0.80)"
cat <<'EOF' > /var/cache/bind/db.lab.test
$TTL 3600
@   IN SOA ns1.lab.test. admin.lab.test. ( 2026101901 3600 600 604800 3600 )
@   IN NS  ns1.lab.test.
ns1 IN A   10.0.0.2
www IN A   10.0.0.80
EOF
chown bind:bind /var/cache/bind/db.lab.test
chmod 777 /var/cache/bind/db.lab.test

echo "[*] 5. Tao file cau hinh Rogue DNS server (GIA MAO, KHONG DNSSEC): /tmp/named-rogue.conf"
cat <<'EOF' > /tmp/named-rogue.conf
options {
    directory "/var/cache/bind";
    listen-on port 53 { 10.0.0.66; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
};

zone "lab.test" {
    type primary;
    file "db.lab.rogue";
};
EOF
chmod 777 /tmp/named-rogue.conf
cp /tmp/named-rogue.conf /etc/bind/named-rogue.conf 2>/dev/null || true
chmod 777 /etc/bind/named-rogue.conf 2>/dev/null || true

echo "[*] 6. Tao file zone gia mao: /var/cache/bind/db.lab.rogue (www -> 6.6.6.6)"
cat <<'EOF' > /var/cache/bind/db.lab.rogue
$TTL 3600
@   IN SOA ns1.lab.test. admin.lab.test. ( 2026101902 3600 600 604800 3600 )
@   IN NS  ns1.lab.test.
ns1 IN A   10.0.0.2
www IN A   6.6.6.6
EOF
chown bind:bind /var/cache/bind/db.lab.rogue
chmod 777 /var/cache/bind/db.lab.rogue

echo "[+] Tat ca cac file cau hinh cho Lab 07 da san sang (quyen 777)!"
