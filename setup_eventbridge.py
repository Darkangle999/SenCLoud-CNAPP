import os
import json
import boto3
from botocore.exceptions import ClientError

def main():
    print("=======================================================")
    print("    ☁️ PROVISIONING ODINEYES AWS EVENT PIPELINE    ")
    print("=======================================================")
    
    # 1. Initialize AWS Session
    region = os.environ.get("ODINEYES_AWS_REGION", "us-east-1")
    profile = os.environ.get("ODINEYES_AWS_PROFILE")
    
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        sqs = session.client('sqs')
        events = session.client('events')
        sts = session.client('sts')
        
        account_id = sts.get_caller_identity()["Account"]
        print(f"[*] Detected AWS Account: {account_id} ({region})")
    except Exception as e:
        print(f"[!] Failed to initialize AWS session: {e}")
        return

    # 2. Create SQS Queue
    queue_name = "Odineyes-EventsQueue"
    print(f"[*] Creating SQS Queue: {queue_name}...")
    
    try:
        response = sqs.create_queue(QueueName=queue_name)
        queue_url = response['QueueUrl']
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
        print(f"   [+] Success! Queue URL: {queue_url}")
    except ClientError as e:
        print(f"   [!] Failed to create SQS Queue: {e}")
        return

    # 3. Attach Resource Policy to allow EventBridge to write to SQS
    print("[*] Attaching Resource Policy to SQS Queue...")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeToSQS",
                "Effect": "Allow",
                "Principal": {
                    "Service": "events.amazonaws.com"
                },
                "Action": "sqs:SendMessage",
                "Resource": queue_arn
            }
        ]
    }
    
    try:
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={'Policy': json.dumps(policy)}
        )
        print("   [+] Success! EventBridge is now allowed to send messages to the Queue.")
    except ClientError as e:
        print(f"   [!] Failed to set SQS Policy: {e}")
        return

    # 4. Create EventBridge Rule
    rule_name = "Odineyes-RealTime-Detection"
    print(f"[*] Creating EventBridge Rule: {rule_name}...")
    
    event_pattern = {
        "source": ["aws.ec2", "aws.iam", "aws.cloudtrail"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": [
                "AuthorizeSecurityGroupIngress",
                "CreateSecurityGroup",
                "AttachRolePolicy",
                "PutRolePolicy",
                "RunInstances",
                "StopLogging",
                "DeleteTrail"
            ]
        }
    }
    
    try:
        events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='Routes high-risk AWS API calls to Odineyes SQS Queue'
        )
        print("   [+] Success! EventBridge rule created.")
    except ClientError as e:
        print(f"   [!] Failed to create EventBridge Rule: {e}")
        return

    # 5. Add SQS Queue as Target for the EventBridge Rule
    print("[*] Linking EventBridge Rule to SQS Queue Target...")
    try:
        events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': 'OdineyesSQSTarget',
                    'Arn': queue_arn
                }
            ]
        )
        print("   [+] Success! Target linked.")
    except ClientError as e:
        print(f"   [!] Failed to add target: {e}")
        return

    # 6. Update docker-compose.yml automatically
    print("[*] Updating docker-compose.yml with new SQS URL...")
    compose_path = "docker-compose.yml"
    
    try:
        with open(compose_path, 'r') as f:
            lines = f.readlines()
            
        with open(compose_path, 'w') as f:
            for line in lines:
                if "ODINEYES_SQS_URL:" in line:
                    continue  # We will add it safely at the end of the block
                f.write(line)
                if "AWS_DEFAULT_REGION: us-east-1" in line:
                    f.write(f'  ODINEYES_SQS_URL: "{queue_url}"\n')
        print("   [+] Success! docker-compose.yml updated.")
    except Exception as e:
        print(f"   [!] Could not automatically update docker-compose.yml: {e}")

    print("\n=======================================================")
    print("✅ EVENT-DRIVEN PIPELINE SUCCESSFULLY DEPLOYED!")
    print("=======================================================")
    print("Run `sudo docker-compose up -d --build` to restart the daemon.")
    print("Then run `python3 trigger_breach.py` to test near-instant detection.")

if __name__ == "__main__":
    main()
