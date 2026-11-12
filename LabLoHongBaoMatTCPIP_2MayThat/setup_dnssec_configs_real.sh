#!/bin/bash
# setup_dnssec_configs_real.sh - Tao cac file cau hinh DNSSEC cho 2 may that tren mang Wi-Fi
set -e

SERVER_IP=${1:-"0.0.0.0"}

echo "=================================================================="
echo "[*] KHOI TAO CAU HINH DNSSEC BIND9 CHO MAY CHU THAT: $SERVER_IP"
echo "=================================================================="

# 1. Xu ly AppArmor
if [ -d /etc/apparmor.d/disable ]; then
    ln -sf /etc/apparmor.d/usr.sbin.named /etc/apparmor.d/disable/ 2>/dev/null || true
    ln -sf /etc/apparmor.d/usr.sbin.unbound /etc/apparmor.d/disable/ 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
    apparmor_parser -R /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
fi

# 2. Tao thu muc va cap quyen
mkdir -p /var/cache/bind /etc/bind /etc/unbound
chmod -R 777 /var/cache/bind
chmod 777 /etc/bind /etc/unbound
chown -R bind:bind /var/cache/bind /etc/bind 2>/dev/null || true
chmod -R 777 /var/cache/bind

# 3. Tao file cau hinh BIND9 chinh chu (CO DNSSEC) lang nghe tren 127.0.0.1:5353
cat <<'EOF' > /etc/bind/named-auth.conf
options {
    directory "/var/cache/bind";
    listen-on port 5353 { 127.0.0.1; };
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
chmod 777 /etc/bind/named-auth.conf
cp /etc/bind/named-auth.conf /tmp/named-auth.conf 2>/dev/null || true

# 4. Tao file zone hop le
cat <<'EOF' > /var/cache/bind/db.lab.test
$TTL 3600
@   IN SOA ns1.lab.test. admin.lab.test. ( 2026101901 3600 600 604800 3600 )
@   IN NS  ns1.lab.test.
ns1 IN A   127.0.0.1
www IN A   10.0.0.80
EOF
chown bind:bind /var/cache/bind/db.lab.test
chmod 777 /var/cache/bind/db.lab.test

# 5. Tao file cau hinh BIND9 gia mao (KHONG DNSSEC) lang nghe tren 127.0.0.1:5354
cat <<'EOF' > /etc/bind/named-rogue.conf
options {
    directory "/var/cache/bind";
    listen-on port 5354 { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
};

zone "lab.test" {
    type primary;
    file "db.lab.rogue";
};
EOF
chmod 777 /etc/bind/named-rogue.conf
cp /etc/bind/named-rogue.conf /tmp/named-rogue.conf 2>/dev/null || true

# 6. Tao file zone gia mao (www -> 6.6.6.6)
cat <<'EOF' > /var/cache/bind/db.lab.rogue
$TTL 3600
@   IN SOA ns1.lab.test. admin.lab.test. ( 2026101902 3600 600 604800 3600 )
@   IN NS  ns1.lab.test.
ns1 IN A   127.0.0.1
www IN A   6.6.6.6
EOF
chown bind:bind /var/cache/bind/db.lab.rogue
chmod 777 /var/cache/bind/db.lab.rogue

echo "[+] Da tao xong toan bo file cau hinh BIND9 cho may that!"
