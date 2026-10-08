#!/usr/bin/env bash
# Deploy the CloudSentinel eBPF sensor to every running EC2 tagged monitor=true,
# via SSM RunShellScript. install-sensor.sh is fetched from the deploy bucket.
#
#   CLOUDSENTINEL_DEPLOY_BUCKET=my-bucket ./ssm-deploy.sh <region> <api-url>
#
# Prereqs: the instances run the SSM agent with an instance profile allowing
# ssm:UpdateInstanceInformation; install-sensor.sh and the sensor code are in
# the deploy bucket (or already synced to /opt/cloudsentinel on each host).
set -euo pipefail

REGION="${1:-us-east-1}"
API_URL="${2:?Usage: ssm-deploy.sh <region> <api-url>}"
BUCKET="${CLOUDSENTINEL_DEPLOY_BUCKET:?set CLOUDSENTINEL_DEPLOY_BUCKET to the deploy bucket}"

INSTANCE_IDS=$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=tag:monitor,Values=true" \
            "Name=instance-state-name,Values=running" \
  --query "Reservations[].Instances[].InstanceId" --output text)

if [ -z "$INSTANCE_IDS" ]; then
  echo "No running instances tagged monitor=true in $REGION" >&2
  exit 1
fi
echo "Deploying sensor to: $INSTANCE_IDS"

# Pull the installer from S3 and run it with the API URL + per-instance host-id.
read -r -d '' CMD <<EOF || true
set -e
aws s3 cp s3://${BUCKET}/cloudsentinel/install-sensor.sh /tmp/install-sensor.sh
chmod +x /tmp/install-sensor.sh
HID=\$(curl -s -m2 -H "X-aws-ec2-metadata-token: \$(curl -s -m2 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)" http://169.254.169.254/latest/meta-data/instance-id)
/tmp/install-sensor.sh ${API_URL} \$HID
EOF

aws ssm send-command \
  --region "$REGION" \
  --instance-ids $INSTANCE_IDS \
  --document-name "AWS-RunShellScript" \
  --comment "CloudSentinel eBPF sensor deploy" \
  --parameters commands="[$(printf '%s' "$CMD" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')]" \
  --query "Command.CommandId" --output text
