#!/usr/bin/env bash
# Probe used by the chaos tests: it logs in once through the real browser flow
# and then keeps requesting the protected route, appending one line per request
# to /logs/probe.log (read by the driver on the host).
#
# A 200 means the session was read from Redis Sentinel successfully (the
# middleware also renews the session on every request, so the write path is
# exercised too), a 302 means the session is gone (re-login), a 503 is the
# documented fail-closed answer when the store is unavailable.
set -u

LOG=/logs/probe.log
JAR=/tmp/probe-jar.txt
BASE=http://traefik
KC=http://keycloak:8080

# The driver truncates the log; a probe restart must keep appending so that the
# outage caused by the previous scenario stays visible.
touch "$LOG"

echo "=== waiting for Keycloak ==="
for _ in $(seq 1 120); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "$KC/realms/myrealm/.well-known/openid-configuration")" = "200" ] && break
    sleep 2
done
echo "=== waiting for Traefik ==="
for _ in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'Accept: application/json' "$BASE/")
    [ "$code" != "000" ] && [ "$code" != "404" ] && [ "$code" != "502" ] && [ "$code" != "503" ] && break
    sleep 2
done

login() {
    rm -f "$JAR"
    curl -s -o /dev/null -D /tmp/h1 -c "$JAR" -m 10 "$BASE/login"
    loc=$(awk 'tolower($1)=="location:"{print $2}' /tmp/h1 | tr -d '\r' | tail -1)
    [ -z "$loc" ] && return 1
    curl -s -o /tmp/login.html -b "$JAR" -c "$JAR" -m 10 "$loc"
    action=$(grep -o 'action="[^"]*"' /tmp/login.html | head -1 | sed 's/action="//; s/"$//; s/&amp;/\&/g')
    [ -z "$action" ] && return 1
    curl -s -o /dev/null -D /tmp/h2 -b "$JAR" -c "$JAR" -m 10 -X POST "$action" \
        --data-urlencode "username=testuser" --data-urlencode "password=testpassword" --data-urlencode "credentialId="
    cb=$(awk 'tolower($1)=="location:"{print $2}' /tmp/h2 | tr -d '\r' | tail -1)
    [ -z "$cb" ] && return 1
    body=$(curl -s -b "$JAR" -c "$JAR" -m 10 -L "$cb")
    printf '%s' "$body" | grep -q "X-Auth-User: testuser"
}

echo "=== logging in ==="
for _ in $(seq 1 30); do
    if login; then
        echo "logged in"
        break
    fi
    sleep 2
done

# The driver writes "MARK <scenario>" lines into the same file, so a scenario is
# analysed on the window between two marks.
started=$(date +%s)
last_login=0
while :; do
    now=$(date +%s)
    out=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -m 15 -b "$JAR" -H 'Accept: text/html' "$BASE/" 2>/dev/null)
    code=${out%% *}
    took=${out#* }
    echo "$((now - started)) $code $took" >>"$LOG"
    # A 302 means the session was lost (for instance because a failover promoted
    # a replica without it): log in again, like a browser would, but keep
    # logging so the outage is visible in the report.
    if [ "$code" = "302" ]; then
        now=$(date +%s)
        # at most one re-login every 5s: the store may be unavailable for a while
        # and a re-login storm would only hammer Keycloak
        if [ $((now - last_login)) -ge 5 ]; then
            last_login=$now
            login >/dev/null 2>&1 || true
        fi
    fi
    sleep 0.3
done
