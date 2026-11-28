#!/usr/bin/env bash
# Loads every configuration example of example/options/ into a real Traefik and
# asserts that it is accepted (the middleware is built, the router is enabled),
# then loads every example of example/options/invalid/ alone and asserts that it
# is rejected with the expected message.
#
# The examples are the per-option, per-variant documentation of the plugin, so
# this script is the "every documented option works" test.
set -u

API=http://traefik:8080
EX=/examples
OPT=/options

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

middlewares() { curl -s -m 10 "$API/api/http/middlewares"; }
routers() { curl -s -m 10 "$API/api/http/routers"; }

router_state() { # $1 = router name -> "status<TAB>error"
    routers | jq -r --arg n "$1" '.[] | select(.name == $n) | "\(.status)\t\(.error // "")"' | head -1
}

echo "=== waiting for Traefik ==="
for _ in $(seq 1 60); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$API/api/http/middlewares")" = "200" ]; then
        echo "traefik is ready"
        break
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
echo "=== 1. every valid example is accepted ==="
rm -f "$OPT"/*.yaml
cp "$EX"/*.yaml "$OPT"/

want=$(grep -vc '^#' "$EX/manifest.tsv")
for _ in $(seq 1 30); do
    got=$(middlewares | jq -r '[.[] | select(.name | endswith("@file"))] | length')
    [ "$got" -ge "$want" ] && break
    sleep 2
done
echo "middlewares built from the examples: $got (expected $want)"

while IFS=$'\t' read -r file mid router; do
    case "$file" in \#* | "") continue ;; esac

    if middlewares | jq -e --arg n "$mid@file" 'any(.[]; .name == $n)' >/dev/null; then
        ok "accepted: $file -> middleware $mid"
    else
        bad "accepted: $file -> middleware $mid is missing"
    fi

    state=$(router_state "$router@file")
    status=$(printf '%s' "$state" | cut -f1)
    err=$(printf '%s' "$state" | cut -f2)
    if [ "$status" = "enabled" ] && [ "$err" = "" ]; then
        ok "router enabled: $router (from $file)"
    else
        bad "router enabled: $router (from $file): status=$status error=$err"
    fi
done <"$EX/manifest.tsv"

# ---------------------------------------------------------------------------
echo "=== 2. inline PEM variant (generated from the mounted test PKI) ==="
{
    printf 'http:\n  middlewares:\n    store-tls-inline-pem:\n      plugin:\n        traefik-keycloak-auth:\n'
    printf '          issuer: "https://keycloak.example.com/realms/myrealm"\n'
    printf '          redirectUrl: "/callback"\n          clientID: "traefik"\n'
    printf '          clientSecret: "secret"\n          secret: "0123456789abcdef0123456789abcdef"\n'
    printf '          session:\n            store:\n              redis:\n                endpoints: ["redis:6379"]\n'
    printf '                tls:\n                  caBundle: |\n'
    sed 's/^/                    /' /tls/ca.crt
    printf '  routers:\n    store-tls-inline-pem:\n      rule: "PathPrefix(`/inline-pem`)"\n'
    printf '      middlewares: ["store-tls-inline-pem"]\n      service: noop@internal\n'
} >"$OPT/zz-store-tls-inline-pem.yaml"

for _ in $(seq 1 20); do
    middlewares | jq -e 'any(.[]; .name == "store-tls-inline-pem@file")' >/dev/null && break
    sleep 1
done
if middlewares | jq -e 'any(.[]; .name == "store-tls-inline-pem@file")' >/dev/null; then
    ok "accepted: inline PEM caBundle (the certificate is parsed from the configuration)"
else
    bad "accepted: inline PEM caBundle"
fi
rm -f "$OPT"/zz-store-tls-inline-pem.yaml

# ---------------------------------------------------------------------------
echo "=== 3. every invalid example is rejected with the expected message ==="
while IFS=$'\t' read -r file mid expect; do
    case "$file" in \#* | "") continue ;; esac

    rm -f "$OPT"/*.yaml
    cp "$EX/invalid/$file" "$OPT/"

    err=""
    status=""
    for _ in $(seq 1 25); do
        state=$(router_state "$mid@file")
        status=$(printf '%s' "$state" | cut -f1)
        err=$(printf '%s' "$state" | cut -f2)
        [ -n "$status" ] && break
        sleep 1
    done

    if [ "$status" = "enabled" ]; then
        bad "rejected: $file was accepted"
    elif printf '%s' "$err" | grep -qF "$expect"; then
        ok "rejected: $file -> $err"
    else
        bad "rejected: $file (status=$status, error=$err, expected '$expect')"
    fi
done <"$EX/invalid/manifest.tsv"

rm -f "$OPT"/*.yaml

echo "-------------------------------"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
