#!/usr/bin/env bash
# Runs the Yaegi compatibility check with the workspace-local Go caches.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
ROOT="$(cd ../.. && pwd)"
export GOCACHE="$ROOT/.gocache" GOTMPDIR="$ROOT/.gotmp" GOMODCACHE="$ROOT/.gomodcache" GOPATH="$ROOT/.gopath" GOFLAGS="-mod=mod"
mkdir -p "$GOCACHE" "$GOTMPDIR" "$GOMODCACHE" "$GOPATH"
go run .
