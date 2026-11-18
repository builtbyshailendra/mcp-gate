#!/usr/bin/env bash
# Starts the demo server and the gate as real processes, drives them with the
# agent CLI, and checks each answer. Used by CI and runnable locally (Git Bash
# on Windows works). Exits non-zero on the first surprise.
set -euo pipefail
cd "$(dirname "$0")/.."

go build -o bin/ ./cmd/...
exe=""; [[ -f bin/mcp-gate.exe ]] && exe=".exe"
rm -f audit.jsonl
./bin/demo-server$exe >/dev/null 2>&1 & demo=$!
./bin/mcp-gate$exe serve -config gate.yaml 2>gate.log & gate=$!
trap 'kill $demo $gate 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:9091/healthz >/dev/null && break; sleep 0.2; done

agent() { ./bin/agent$exe "$@"; }
expect() { # expect <description> <want-substring> <command...>
  local what=$1 want=$2; shift 2
  local got; got=$("$@" 2>&1 || true)
  if [[ $got != *"$want"* ]]; then echo "FAIL  $what"; echo "      want: $want"; echo "      got:  $got"; exit 1; fi
  echo "ok    $what"
}

expect "docs-bot sees read tools only" "list_pods" agent -token demo-docs-token tools
[[ $(agent -token demo-docs-token tools) != *scale_deployment* ]] || { echo "FAIL  docs-bot sees scale_deployment"; exit 1; }
expect "docs-bot can't scale" "default deny" \
  agent -token demo-docs-token call scale_deployment '{"namespace":"staging-payments","deployment":"api","replicas":2}'
expect "on-call scales prod" "from 3 to 5" \
  agent -token demo-oncall-token call scale_deployment '{"namespace":"prod-payments","deployment":"api","replicas":5}'
expect "never scale prod to zero" "never-scale-prod-to-zero" \
  agent -token demo-oncall-token call scale_deployment '{"namespace":"prod-payments","deployment":"api","replicas":0}'
expect "destructive tools blocked" "no-destructive-tools" \
  agent -token demo-oncall-token call delete_namespace '{"namespace":"dev-sandbox"}'
expect "older protocol works" "api-4" \
  agent -protocol 2025-11-25 -token demo-docs-token call list_pods '{"namespace":"prod-payments"}'
expect "unknown token refused" "Unauthorized" agent -token nope tools
expect "metrics count the denials" 'mcpgate_decisions_total{agent="oncall-bot",decision="deny",tool="delete_namespace"} 1' \
  curl -s http://127.0.0.1:9091/metrics
expect "audit names the policy" '"policies":["never-scale-prod-to-zero"]' cat audit.jsonl
echo "smoke test passed"
