#!/usr/bin/env bash
# Chaos testing driver (runs on the host, drives the chaos stack):
# it starts the stack with the probe, injects one failure at a time (Sentinel
# failover, killed Redis/Sentinels, poisoned key, blocked server, restarted
# Traefik) and reports, per scenario, the status distribution seen by the probe,
# the longest failure streak and the recovery time.
#
#   docker/chaos.sh                 # full run, report on stdout
#   OUT=docs/artifacts/chaos.txt docker/chaos.sh
set -u

cd "$(dirname "$0")/.." || exit 1

COMPOSE="docker compose -p plugin-chaos -f docker-compose.chaos.yaml"
LOG="docker/chaos-runtime/probe.log"
OUT="${OUT:-docker/chaos-runtime/chaos-report.txt}"
REPORT_KEEP="${REPORT_KEEP:-1}"

pass=0
fail=0

# ---------------------------------------------------------------- helpers
mark() { echo "MARK $1" >>"$LOG"; }

logtail() { tail -n 400 "$LOG" 2>/dev/null; }

is_master() { # $1 = container -> success when it plays the master role
    docker exec "$1" redis-cli INFO replication 2>/dev/null | tr -d '\r' | grep -q '^role:master'
}

# A container that is still starting answers nothing, so poll: the role must be
# determined reliably, otherwise a scenario would silently do nothing.
current_master() {
    for _ in $(seq 1 30); do
        for c in chaos-redis-master chaos-redis-replica; do
            if is_master "$c"; then echo "$c"; return 0; fi
        done
        sleep 1
    done
}

current_replica() {
    for _ in $(seq 1 30); do
        for c in chaos-redis-master chaos-redis-replica; do
            if docker exec "$c" redis-cli INFO replication 2>/dev/null | tr -d '\r' | grep -q '^role:slave'; then
                echo "$c"
                return 0
            fi
        done
        sleep 1
    done
}

wait_code() { # $1 = wanted code, $2 = consecutive count, $3 = timeout s
    want=$1
    need=$2
    deadline=$(( $(date +%s) + $3 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        got=$(logtail | awk '{print $2}' | tail -n "$need" | grep -c "^$want$")
        [ "$got" -ge "$need" ] && return 0
        sleep 1
    done
    return 1
}

# Rebuilds a coherent topology: the test Sentinels regenerate their configuration
# from the compose command on every start, so after a failover they can announce
# a node that is not the master any more. Restarting the data nodes (which
# re-apply the original roles) and resetting the Sentinels brings the stack back
# to the documented baseline, so the next scenario starts from a known state.
reset_cluster() {
    echo "resetting the Redis/Sentinel topology of the test stack"
    docker restart chaos-redis-master chaos-redis-replica >/dev/null 2>&1
    sleep 8
    for s in chaos-sentinel-0 chaos-sentinel-1 chaos-sentinel-2; do
        docker restart "$s" >/dev/null 2>&1
    done
    sleep 10
    for s in chaos-sentinel-0 chaos-sentinel-1 chaos-sentinel-2; do
        docker exec "$s" redis-cli -p 26379 SENTINEL RESET mymaster >/dev/null 2>&1
    done
    sleep 12
}

restart_probe() { # a fresh browser session (the previous scenario may have lost it)
    echo "restarting the probe (fresh login)"
    docker restart chaos-probe >/dev/null 2>&1
    sleep 5
    wait_code 200 5 120
}

settle() {
    if wait_code 200 5 90; then
        pass=$((pass + 1))
        echo "OK: the probe is healthy again (5 consecutive 200s)"
    else
        fail=$((fail + 1))
        echo "FAIL: the probe did not recover within 90s"
    fi
}

scenario() { # $1 = name; the caller performs the action
    echo
    echo "=== $1 ==="
    mark "BEGIN $1"
    sleep 2
}

# ---------------------------------------------------------------- stack
echo "=== starting the chaos stack ==="
$COMPOSE down -v --remove-orphans >/dev/null 2>&1
rm -f "$LOG"
$COMPOSE up -d --build >/dev/null 2>&1
for _ in $(seq 1 120); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -H 'Accept: application/json' http://localhost:9280/ 2>/dev/null)
    [ "$code" = "401" ] && break
    sleep 2
done
echo "traefik answered $code"

echo "=== waiting for the probe to log in ==="
for _ in $(seq 1 90); do
    grep -q "^[0-9]* [0-9]" "$LOG" 2>/dev/null && break
    sleep 2
done
wait_code 200 3 60 && echo "probe is serving 200s" || echo "WARN: no 200s yet"

# ---------------------------------------------------------------- scenarios
scenario "1. baseline (no failure injected, 15s)"
sleep 15

scenario "2. Sentinel failover"
docker exec chaos-sentinel-0 redis-cli -p 26379 SENTINEL failover mymaster >/dev/null 2>&1
sleep 20
settle

scenario "3. current replica killed (must be transparent)"
replica=$(current_replica)
echo "the replica is ${replica:-UNKNOWN}"
if [ -z "$replica" ]; then
    fail=$((fail + 1))
    echo "FAIL: could not determine the replica role"
fi
[ -n "$replica" ] && docker kill "$replica" >/dev/null 2>&1
sleep 15
[ -n "$replica" ] && docker start "$replica" >/dev/null 2>&1
sleep 10
settle

scenario "4. current master killed (hard failover)"
master=$(current_master)
echo "the master is ${master:-UNKNOWN}"
if [ -z "$master" ]; then
    fail=$((fail + 1))
    echo "FAIL: could not determine the master role"
fi
[ -n "$master" ] && docker kill "$master" >/dev/null 2>&1
sleep 30
[ -n "$master" ] && docker start "$master" >/dev/null 2>&1
sleep 15
settle

scenario "5. all Sentinels killed (discovery down, data path up)"
docker kill chaos-sentinel-0 chaos-sentinel-1 chaos-sentinel-2 >/dev/null 2>&1
sleep 20
docker start chaos-sentinel-0 chaos-sentinel-1 chaos-sentinel-2 >/dev/null 2>&1
sleep 10
# The Sentinels of this stack rebuild their configuration from the compose
# command on every start, so they would announce `redis-master` again even when
# the failover promoted the other node. RESET makes them re-scan the actual
# topology, exactly like a Sentinel with a persisted state would know it.
reset_cluster
restart_probe >/dev/null 2>&1 || true
settle

restart_probe >/dev/null 2>&1 || true
scenario "6. Redis master blocked for 8s (CLIENT PAUSE ALL)"
master=$(current_master)
echo "the master is ${master:-UNKNOWN}"
if [ -z "$master" ]; then
    fail=$((fail + 1))
    echo "FAIL: could not determine the master role (the scenario is skipped)"
fi
# CLIENT PAUSE ALL freezes every client of the instance for the given time, which
# is a reliable "slow/unresponsive store" than DEBUG SLEEP (whose window can fall
# between two probe requests).
[ -n "$master" ] && docker exec "$master" redis-cli -t 20 CLIENT PAUSE 8000 ALL >/dev/null 2>&1
sleep 20
settle

restart_probe >/dev/null 2>&1 || true
scenario "7. Traefik restarted"
docker restart chaos-traefik >/dev/null 2>&1
sleep 20
settle

scenario "8. WRONGTYPE poisoned key on the master (self-healing)"
master=$(current_master)
echo "the master is ${master:-UNKNOWN}"
if [ -z "$master" ]; then
    fail=$((fail + 1))
    echo "FAIL: could not determine the master role (the scenario is skipped)"
fi
poisoned=0
# Target the session the probe is actually using (read from its cookie jar inside
# the container): poisoning a stale key would never be read, and the self-heal
# path would stay unexercised.
probe_session=$(docker exec chaos-probe sh -c 'grep -o "toa-session[[:space:]]*[0-9a-f-]*" /tmp/probe-jar.txt 2>/dev/null | awk "{print \$2}"' 2>/dev/null | tail -1)
if [ -n "$probe_session" ]; then
    docker exec "$master" redis-cli SADD "toa:session:$probe_session" "poisoned" >/dev/null 2>&1
    poisoned=$((poisoned + 1))
    echo "poisoned the session of the probe (toa:session:$probe_session)"
fi
if [ -n "$master" ]; then
    for victim in $(docker exec "$master" redis-cli --scan --pattern 'toa:session:*' 2>/dev/null); do
        # SADD creates a *set* where a string is expected: the plugin's GET then
        # answers WRONGTYPE, which must be healed instead of failing the store
        docker exec "$master" redis-cli SADD "$victim" "poisoned" >/dev/null 2>&1
        poisoned=$((poisoned + 1))
    done
fi
echo "poisoned $poisoned session key(s) on the master (a set in place of the string)"
if [ "$poisoned" -eq 0 ]; then
    fail=$((fail + 1))
    echo "FAIL: no session key to poison"
fi
sleep 3
restart_probe && { pass=$((pass+1)); echo "OK: the probe logged in again after the heal"; } || { fail=$((fail+1)); echo "FAIL: the probe could not log in after the heal"; }
settle


scenario "9. both data nodes killed (store outage, fail closed)"
docker kill chaos-redis-master chaos-redis-replica >/dev/null 2>&1
sleep 25
docker start chaos-redis-master chaos-redis-replica >/dev/null 2>&1
sleep 25
settle

sleep 3

# ---------------------------------------------------------------- report
echo
echo "=== collecting evidence from the Traefik log ==="
EVIDENCE="docker/chaos-runtime/traefik-chaos.log"
$COMPOSE logs traefik >"$EVIDENCE" 2>&1 || true
grep -cE "master switched" "$EVIDENCE" | sed 's/^/master switches: /'
grep -cE "Session store unavailable" "$EVIDENCE" | sed 's/^/store-unavailable log lines: /'
healed=$(grep -cF "Dropped the Redis key" "$EVIDENCE")
echo "self-heal log lines: $healed"
if [ "$healed" -ge 1 ]; then
    pass=$((pass + 1))
    echo "OK: the WRONGTYPE key was healed (the plugin logged it and kept serving)"
else
    fail=$((fail + 1))
    echo "FAIL: no self-heal log line, the poisoned key was not exercised"
fi
grep -cE "%!" "$EVIDENCE" | sed 's/^/malformed error markers (must be 0): /'

echo
echo "=== scenario report ==="
python3 docker/chaos-report.py "$LOG" | tee "$OUT"

$COMPOSE stop probe >/dev/null 2>&1 || true

echo
echo "raw probe log: $LOG"
echo "report:        $OUT"
echo "traefik log:   $EVIDENCE"
[ "$fail" -eq 0 ] || echo "WARN: $fail scenario(s) did not recover automatically"
