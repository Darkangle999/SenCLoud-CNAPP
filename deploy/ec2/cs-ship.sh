#!/usr/bin/env bash
# Ship NEW bytes of the eBPF spool to S3 as a unique object, advancing a byte
# offset so each run uploads only fresh events. The S3 prefix acts as a queue
# the local drain daemon consumes (download -> ingest -> delete).
#
# Config comes from /etc/cloudsentinel/ship.env (EnvironmentFile in the unit):
#   SPOOL, OFFSET, BUCKET, PREFIX, AWS_REGION
set -euo pipefail

: "${SPOOL:=/var/lib/cloudsentinel/spool.jsonl}"
: "${OFFSET:=/var/lib/cloudsentinel/.offset}"
: "${BUCKET:?BUCKET unset}"
: "${PREFIX:?PREFIX unset}"
: "${AWS_REGION:?AWS_REGION unset}"

[ -f "$SPOOL" ] || exit 0
size=$(stat -c%s "$SPOOL")
off=$(cat "$OFFSET" 2>/dev/null || echo 0)

# Rotated/truncated since last run -> start from the top.
[ "$size" -lt "$off" ] && off=0
# Nothing new.
[ "$size" -le "$off" ] && exit 0

chunk=$(mktemp)
trap 'rm -f "$chunk"' EXIT
tail -c +$((off + 1)) "$SPOOL" > "$chunk"
[ -s "$chunk" ] || exit 0

key="${PREFIX%/}/$(date -u +%Y%m%dT%H%M%S)-$$-${RANDOM}.jsonl"
aws s3 cp "$chunk" "s3://${BUCKET}/${key}" --region "$AWS_REGION" --only-show-errors
echo "$size" > "$OFFSET"
