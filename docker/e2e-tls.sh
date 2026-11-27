#!/usr/bin/env bash
# End-to-end test driven from inside the compose network, against the
# Sentinel+TLS stack: every Redis/Sentinel connection is TLS with mutual
# authentication.
#
# It exercises the full authorization-code + PKCE flow against a real Keycloak,
# the Redis Sentinel session store over TLS (including a live failover), the
# CSRF protection, forwardHeaders, the back-channel logout endpoint, the mTLS
# enforcement of the store and the readable-error path of a wrong credential.
set -u

BASE=http://traefik
KC=http://keycloak:8080
JAR=/tmp/jar.txt
JAR2=/tmp/jar2.txt

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }
check() {
    if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1: got '$2', want '$3'"; fi
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# Every Redis/Sentinel connection needs the test CA and the client certificate.
RCLI="redis-cli --tls --cacert /tls/ca.crt --cert /tls/client.crt --key /tls/client.key"
location() { awk 'tolower($1)=="location:"{print $2}' "$1" | tr -d '\r' | tail -1; }

echo "=== waiting for Keycloak ==="
for _ in $(seq 1 90); do
    if [ "$(status "$KC/realms/myrealm/.well-known/openid-configuration")" = "200" ]; then
        ok "Keycloak is ready"
        break
    fi
    sleep 2
done

echo "=== waiting for Traefik + plugin ==="
traefik_code=""
for _ in $(seq 1 90); do
    traefik_code=$(status -H 'Accept: application/json' "$BASE/")
    case "$traefik_code" in
    000 | 404 | 502 | 503) sleep 2 ;;
    *) break ;;
    esac
done
echo "traefik answered $traefik_code on /"

# ---------------------------------------------------------------------------
echo "=== 1. unauthenticated request ==="
check "unauthenticated / returns 401" "$(status -H 'Accept: application/json' "$BASE/")" "401"

# ---------------------------------------------------------------------------
echo "=== 2. /login redirects to Keycloak with PKCE ==="
curl -s -o /dev/null -D /tmp/h1 -c "$JAR" "$BASE/login"
login_loc=$(location /tmp/h1)
case "$login_loc" in
*"$KC/realms/myrealm/protocol/openid-connect/auth"*) ok "login redirects to Keycloak" ;;
*) bad "login redirects to Keycloak (got '$login_loc')" ;;
esac
case "$login_loc" in
*"code_challenge_method=S256"*) ok "the PKCE challenge is present" ;;
*) bad "the PKCE challenge is present" ;;
esac
case "$login_loc" in
*"client_id=traefik"*) ok "the client_id is correct" ;;
*) bad "the client_id is correct" ;;
esac

# ---------------------------------------------------------------------------
echo "=== 3. Keycloak login page + credentials ==="
curl -s -o /tmp/login.html -b "$JAR" -c "$JAR" "$login_loc"
action=$(grep -o 'action="[^"]*"' /tmp/login.html | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
if [ -n "$action" ]; then ok "the Keycloak login form was found"; else bad "the Keycloak login form was found"; fi

curl -s -o /dev/null -D /tmp/h2 -b "$JAR" -c "$JAR" -X POST "$action" \
    --data-urlencode "username=testuser" --data-urlencode "password=testpassword" --data-urlencode "credentialId="
callback_loc=$(location /tmp/h2)
case "$callback_loc" in
*"/callback?"*"code="*) ok "Keycloak redirects back with an authorization code" ;;
*) bad "Keycloak redirects back with an authorization code (got '$callback_loc')" ;;
esac

# ---------------------------------------------------------------------------
echo "=== 4. callback + upstream headers ==="
code=$(curl -s -o /tmp/whoami.txt -w '%{http_code}' -b "$JAR" -c "$JAR" -L "$callback_loc")
check "the authenticated request reaches the upstream" "$code" "200"
grep -q "X-Auth-User: testuser" /tmp/whoami.txt && ok "forwardHeaders sets X-Auth-User" || bad "forwardHeaders sets X-Auth-User"
grep -qi "X-Auth-Roles:" /tmp/whoami.txt && ok "forwardHeaders sets X-Auth-Roles (array claim)" || bad "forwardHeaders sets X-Auth-Roles (array claim)"
grep -qi "X-Id-Token:" /tmp/whoami.txt && ok "forwardIDTokenHeader sets X-Id-Token" || bad "forwardIDTokenHeader sets X-Id-Token"
grep -qi "Authorization: Bearer" /tmp/whoami.txt && ok "forwardAccessToken sets Authorization: Bearer" || bad "forwardAccessToken sets Authorization: Bearer"

# ---------------------------------------------------------------------------
echo "=== 5. session stored in Redis Sentinel ==="
# mTLS must be enforced by the store: without a client certificate the TLS
# handshake is refused.
if $RCLI --cert "" --key "" -h redis-master -p 6379 PING >/dev/null 2>&1; then
    bad "Redis accepts a TLS connection without a client certificate"
else
    ok "Redis refuses a TLS connection without a client certificate (mTLS enforced)"
fi

master=$($RCLI -h sentinel-0 -p 26379 sentinel get-master-addr-by-name mymaster | head -1)
if [ -n "$master" ]; then ok "Sentinel resolves the master over TLS ($master)"; else bad "Sentinel resolves the master over TLS"; fi
keys=$($RCLI -h "$master" -p 6379 --scan --pattern 'toa:session:*' 2>/dev/null | head -3 | tr '\n' ' ')
if [ -n "$keys" ]; then ok "the session is stored in Redis over TLS ($keys)"; else bad "the session is stored in Redis over TLS"; fi

# ---------------------------------------------------------------------------
echo "=== 6. CSRF protection ==="
curl -s -o /dev/null -D /tmp/h3 -b "$JAR" -c "$JAR" -H 'Accept: text/html' "$BASE/"
csrf=$(awk '/hub-csrf-token/{print $7}' "$JAR" | tail -1)
if [ -n "$csrf" ]; then ok "the CSRF cookie was issued"; else bad "the CSRF cookie was issued"; fi
check "POST without the CSRF header is rejected" "$(status -b "$JAR" -X POST "$BASE/")" "403"
check "POST with the CSRF header is accepted" "$(status -b "$JAR" -H "Hub-Csrf-Token: $csrf" -X POST "$BASE/")" "200"

# ---------------------------------------------------------------------------
echo "=== 7. back-channel logout endpoint ==="
check "back-channel logout without a token is rejected" "$(status -X POST "$BASE/backchannel-logout")" "400"
check "back-channel logout with a forged token is rejected" "$(status -X POST "$BASE/backchannel-logout" --data-urlencode 'logout_token=not.a.jwt')" "400"

# ---------------------------------------------------------------------------
echo "=== 8. Redis Sentinel failover keeps the data path alive ==="
$RCLI -h sentinel-0 -p 26379 sentinel failover mymaster >/dev/null 2>&1
sleep 6
# A failover is asynchronous: the plugin may hit the demoted master for a short
# window and correctly fails closed. The requirement is that the data path
# recovers on its own, so allow a bounded recovery window instead of sampling
# one instant. No -c: an unauthenticated reply clears the session cookie and
# letting curl persist that would destroy the very session we are probing.
code=""
for _ in $(seq 1 45); do
    code=$(status -b "$JAR" -H 'Accept: text/html' "$BASE/")
    case "$code" in
    5* | 000) sleep 1 ;;
    *) break ;;
    esac
done
case "$code" in
5* | 000) bad "the plugin recovered after the failover (got $code, want no 5xx)" ;;
*) ok "the plugin recovered after the failover (got $code)" ;;
esac

# Recovery of the connection is not enough: the failover must leave a working
# write+read data path. A fresh login against the promoted master proves it (the
# pre-failover session may legitimately be lost to async replication, which the
# 302 above would show); a failover can take a while, so retry in a bounded
# window instead of sampling one instant (a manual failover can take a while).
logged_in=0
for attempt in $(seq 1 12); do
    JAR3="/tmp/jar3-$attempt.txt"
    curl -s -o /dev/null -D /tmp/h5 -c "$JAR3" "$BASE/login"
    loc5=$(location /tmp/h5)
    if [ -z "$loc5" ]; then sleep 5; continue; fi
    curl -s -o /tmp/login5.html -b "$JAR3" -c "$JAR3" "$loc5"
    action5=$(grep -o 'action="[^"]*"' /tmp/login5.html | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
    if [ -z "$action5" ]; then sleep 5; continue; fi
    curl -s -o /dev/null -D /tmp/h6 -b "$JAR3" -c "$JAR3" -X POST "$action5" \
        --data-urlencode "username=testuser" --data-urlencode "password=testpassword" --data-urlencode "credentialId="
    cb5=$(location /tmp/h6)
    body5=$(curl -s -b "$JAR3" -c "$JAR3" -L "$cb5")
    if printf '%s' "$body5" | grep -q "X-Auth-User: testuser"; then logged_in=1; break; fi
    sleep 5
done
if [ "$logged_in" = "1" ]; then
    ok "a new session works against the master promoted by the failover"
else
    bad "a new session works against the master promoted by the failover"
fi

newmaster=$($RCLI -h sentinel-0 -p 26379 sentinel get-master-addr-by-name mymaster | head -1)
if [ -n "$newmaster" ]; then ok "Sentinel resolves a master after the failover ($newmaster)"; else bad "Sentinel resolves a master after the failover"; fi

# ---------------------------------------------------------------------------
echo "=== 9. cookie session storage middleware ==="
check "the cookie middleware protects /cookie" "$(status -H 'Accept: application/json' "$BASE/cookie/")" "401"
curl -s -o /dev/null -D /tmp/h4 -c "$JAR2" "$BASE/cookie/login"
case "$(location /tmp/h4)" in
*"$KC/realms/myrealm"*) ok "the cookie middleware redirects to Keycloak" ;;
*) bad "the cookie middleware redirects to Keycloak" ;;
esac

# ---------------------------------------------------------------------------
echo "=== 10. Redis/Sentinel over TLS: mTLS, wrong credentials ==="
# The plugin's TLS options must reach the store: with the wrong CA it cannot
# connect, with the right one it can (the checks above prove the latter).
if $RCLI --cacert /dev/null -h redis-master -p 6379 PING >/dev/null 2>&1; then
    bad "Redis accepts a connection with an empty trust store"
else
    ok "Redis rejects the connection when no CA is trusted"
fi

# A wrong credential must fail closed (503) - the message itself is checked
# from the Traefik log on the host side.
# A session cookie is what makes the middleware read the store, which is where
# the wrong credential must be noticed (and reported readably, see the log).
check "the middleware with wrong store credentials fails closed" "$(status -b 'toa-session=deadbeef' -H 'Accept: application/json' "$BASE/badcreds/")" "503"

echo "-------------------------------"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
