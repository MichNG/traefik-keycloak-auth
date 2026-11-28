#!/usr/bin/env bash
# Load-test runner for the Docker end-to-end stack.
#
# It brings the stack up (reusing docker-compose.yaml through the
# docker-compose.load.yaml overlay under the same project name "plugin"), waits
# for Keycloak and Traefik, then runs tools/loadtest in the three modes
# (unauth, session, cookie) and prints the three reports in sequence.
#
#   docker/loadtest.sh
#
# Environment overrides: SESSIONS (default 30), CONCURRENCY (default 20),
# DURATION (default 30s). Tear the stack down afterwards with:
#   docker compose -p plugin -f docker-compose.yaml -f docker-compose.load.yaml down -v
set -u

cd "$(dirname "$0")/.."

COMPOSE=(docker compose -p plugin -f docker-compose.yaml -f docker-compose.load.yaml)
BASE=http://localhost:9080
SESSIONS=${SESSIONS:-30}
CONCURRENCY=${CONCURRENCY:-20}
DURATION=${DURATION:-30s}

# Only the infrastructure services. The `tester` service of docker-compose.yaml
# is intentionally left out: its e2e.sh triggers a Redis Sentinel failover, which
# would perturb the load test. The `loadtest` service is run one-off below.
SERVICES=(keycloak keycloak-postgres redis-master redis-replica sentinel-0 sentinel-1 sentinel-2 traefik whoami)

echo "=== bringing the stack up (project plugin) ==="
"${COMPOSE[@]}" up -d --build "${SERVICES[@]}"
# Make sure a tester left over from a previous `up -d` cannot interfere.
"${COMPOSE[@]}" rm -sf tester >/dev/null 2>&1 || true

echo "=== waiting for Keycloak ==="
if "${COMPOSE[@]}" run --rm --no-deps -T tester sh -c \
    'for i in $(seq 1 120); do wget -q -O /dev/null http://keycloak:8080/realms/myrealm/.well-known/openid-configuration && { echo "keycloak ready"; exit 0; }; sleep 2; done; echo "keycloak timed out"; exit 1'; then
    :
else
    echo "Keycloak did not become ready" >&2
    exit 1
fi

echo "=== waiting for Traefik + plugin ==="
traefik_code=""
for _ in $(seq 1 90); do
    traefik_code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json' "$BASE/")
    case "$traefik_code" in
    200 | 301 | 302 | 401) break ;;
    *) sleep 2 ;;
    esac
done
case "$traefik_code" in
200 | 301 | 302 | 401) ;;
*)
    echo "Traefik did not become ready (last code $traefik_code)" >&2
    exit 1
    ;;
esac
echo "traefik answered $traefik_code on $BASE/"

run_mode() {
    local mode=$1
    shift
    echo
    echo "################################################################"
    echo "### load mode: $mode"
    echo "################################################################"
    "${COMPOSE[@]}" --profile load run --rm -T loadtest \
        go -C tools/loadtest run . \
        -base http://traefik -mode "$mode" \
        -sessions "$SESSIONS" -concurrency "$CONCURRENCY" -duration "$DURATION" "$@"
}

# 1) plain unauthenticated requests -> 401
run_mode unauth
# 2) Redis-Sentinel backed sessions (sliding writes on the plugin side)
run_mode session
# 3) cookie-session middleware, target /cookie
run_mode cookie

echo
echo "=== all three load modes finished ==="
