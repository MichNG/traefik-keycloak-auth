.PHONY: test test-race cover lint yaegi-check vendor certs integration integration-down integration-tls integration-tls-down options options-down loadtest chaos chaos-down loadtest

# Runs gofmt, go vet and the whole test suite. The Go caches are kept inside
# the repository so that the target also works in restricted environments.
test:
	@./run-tests.sh -count=1

test-race:
	@./run-tests.sh -race -count=1

cover:
	@./run-tests.sh -count=1 -covermode=atomic -coverprofile=coverage.txt
	@go tool cover -html=coverage.txt -o cover.html

lint:
	@fmt=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^vendor/')); \
	 if [ -n "$$fmt" ]; then echo "not gofmt-ed:"; echo "$$fmt"; exit 1; fi
	@go vet ./...

# Loads the plugin with the same Yaegi interpreter as Traefik (v0.16.1) and
# drives a few requests through it.
yaegi-check:
	@tools/yaegicheck/run.sh

# Traefik can only resolve the third-party dependencies of a plugin from the
# vendor/ directory; run this after changing go.mod.
vendor:
	@go mod tidy
	@go mod vendor

# Keycloak + Redis Sentinel end-to-end test (real authorization-code flow).
integration:
	@docker compose -f docker-compose.yaml up -d --build
	@docker compose -f docker-compose.yaml run --rm tester

integration-down:
	@docker compose -f docker-compose.yaml down -v --remove-orphans

# Generates the test PKI for the Sentinel+TLS stack (docker/tls/out, not committed).
certs:
	@docker/tls/generate-certs.sh

# Keycloak + Redis Sentinel end-to-end test where every Redis/Sentinel connection
# is TLS with mutual authentication. A separate compose project name, so it can
# run next to the plain stack.
integration-tls: certs
	@docker compose -p plugin-tls -f docker-compose.sentinel-tls.yaml up -d --build
	@docker compose -p plugin-tls -f docker-compose.sentinel-tls.yaml run --rm tester

integration-tls-down:
	@docker compose -p plugin-tls -f docker-compose.sentinel-tls.yaml down -v --remove-orphans

# Load test of the running stack: brings the stack up and runs tools/loadtest in
# the three modes (unauth, session, cookie). See docker/loadtest.sh.
loadtest:
	@docker/loadtest.sh

# Loads every example of example/options/ (and rejects every example of
# example/options/invalid/) into a real Traefik: the per-option test.
options: certs
	@docker compose -p plugin-options -f docker-compose.options.yaml up -d --build
	@docker compose -p plugin-options -f docker-compose.options.yaml run --rm tester

options-down:
	@docker compose -p plugin-options -f docker-compose.options.yaml down -v --remove-orphans

# Chaos testing: injects failures (failover, killed nodes, poisoned keys, a
# blocked master) while a probe drives traffic, then prints the per-scenario
# report. See docker/chaos.sh.
chaos:
	@docker/chaos.sh

chaos-down:
	@docker compose -p plugin-chaos -f docker-compose.chaos.yaml down -v --remove-orphans
