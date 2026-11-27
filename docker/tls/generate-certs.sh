#!/usr/bin/env bash
# Generates the PKI used by the Sentinel+TLS end-to-end test:
#   ca.crt/ca.key          the test CA
#   server.crt/server.key  a certificate valid for every service host name
#   client.crt/client.key  the client certificate the plugin presents (mTLS)
#
# The output directory (docker/tls/out) is generated, never committed.
set -euo pipefail

cd "$(dirname "$0")"
OUT="out"
rm -rf "$OUT"
mkdir -p "$OUT"

HOSTS="redis-master redis-replica sentinel-0 sentinel-1 sentinel-2 localhost"
# The compose file pins the stack to a fixed subnet (needed because a Sentinel
# failover can announce the promoted node by IP); the same addresses must be
# valid for the certificate.
IPS="127.0.0.1 172.31.0.10 172.31.0.11 172.31.0.20 172.31.0.21 172.31.0.22"
SAN=""
for h in $HOSTS; do SAN="$SAN,DNS:$h"; done
for ip in $IPS; do SAN="$SAN,IP:$ip"; done
SAN="${SAN#,}"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
    -subj "/CN=traefik-keycloak-auth test CA" >/dev/null 2>&1

# Server certificate (used by Redis and by the Sentinels)
openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUT/server.key" -out "$OUT/server.csr" \
    -subj "/CN=redis" >/dev/null 2>&1
cat > "$OUT/server.ext" <<EXT
subjectAltName=$SAN
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=CA:FALSE
EXT
openssl x509 -req -days 3650 -in "$OUT/server.csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -extfile "$OUT/server.ext" -out "$OUT/server.crt" >/dev/null 2>&1

# Client certificate (mTLS from the plugin to Redis/Sentinel)
openssl req -newkey rsa:2048 -nodes \
    -keyout "$OUT/client.key" -out "$OUT/client.csr" \
    -subj "/CN=traefik-keycloak-auth client" >/dev/null 2>&1
cat > "$OUT/client.ext" <<EXT
extendedKeyUsage=clientAuth
basicConstraints=CA:FALSE
EXT
openssl x509 -req -days 3650 -in "$OUT/client.csr" \
    -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
    -extfile "$OUT/client.ext" -out "$OUT/client.crt" >/dev/null 2>&1

rm -f "$OUT"/*.csr "$OUT"/*.ext "$OUT"/*.srl
chmod 644 "$OUT"/*.crt "$OUT"/*.key
echo "PKI written to $OUT:"
ls -1 "$OUT"
