#!/bin/bash
# Script to deploy EventBridge -> SQS infrastructure for CloudSentinel Sub-Second Monitoring

set -e

REGION=${1:-us-east-1}
QUEUE_NAME="cloudsentinel-realtime-queue"
RULE_NAME="cloudsentinel-realtime-rule"

echo "🚀 Deploying CloudSentinel Real-Time Infrastructure in $REGION..."

# 1. Create SQS Queue
echo "📦 Creating SQS Queue: $QUEUE_NAME"
QUEUE_URL=$(aws sqs create-queue --queue-name $QUEUE_NAME --region $REGION --query 'QueueUrl' --output text)
QUEUE_ARN=$(aws sqs get-queue-attributes --queue-url $QUEUE_URL --attribute-names QueueArn --region $REGION --query 'Attributes.QueueArn' --output text)

echo "   Queue URL: $QUEUE_URL"

# 2. Set SQS Policy to allow EventBridge to send messages
echo "🔒 Applying SQS Policy to allow EventBridge..."
POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "$QUEUE_ARN"
    }
  ]
}
EOF
)
aws sqs set-queue-attributes --queue-url $QUEUE_URL --attributes Policy="$POLICY" --region $REGION

# 3. Create EventBridge Rule
echo "⚡ Creating EventBridge Rule: $RULE_NAME"
# We match mutating API calls via CloudTrail (requires CloudTrail to be enabled in the account)
EVENT_PATTERN=$(cat <<EOF
{
  "source": ["aws.s3", "aws.ec2", "aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"]
}
EOF
)
aws events put-rule --name $RULE_NAME --event-pattern "$EVENT_PATTERN" --state ENABLED --region $REGION

# 4. Add SQS as Target
echo "🎯 Adding SQS as EventBridge Target..."
aws events put-targets --rule $RULE_NAME --targets "Id"="1","Arn"="$QUEUE_ARN" --region $REGION

echo ""
echo "✅ Deployment Complete! Sub-second infrastructure is ready."
echo ""
echo "Start listening for real-time events by running:"
echo "cloudsentinel listen --queue-url $QUEUE_URL"
echo ""
echo "To clean up later:"
echo "aws events remove-targets --rule $RULE_NAME --ids 1 --region $REGION"
echo "aws events delete-rule --name $RULE_NAME --region $REGION"
echo "aws sqs delete-queue --queue-url $QUEUE_URL --region $REGION"
