"""
Odineyes - Event Listener Engine
Listens for real-time AWS CloudTrail events via SQS to trigger targeted scans.
"""

import time
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Generator, Optional
from rich.console import Console

from odineyes.utils.logger import setup_logger

logger = setup_logger()


class EventListener:
    """
    Polls AWS CloudTrail directly to capture real-time API events.
    Alternatively, polls an SQS queue populated by EventBridge for sub-second latency.
    """

    def __init__(self, profile: str = "default", region: Optional[str] = None, queue_url: Optional[str] = None):
        self.profile = profile
        self.console = Console()
        self.seen_events = set()
        self.queue_url = queue_url
        
        self.cloudtrail = None
        self.sqs = None
        try:
            import boto3
            session = boto3.Session(profile_name=self.profile, region_name=region)
            self.region = session.region_name or "us-east-1"
            
            if self.queue_url:
                self.sqs = session.client('sqs', region_name=self.region)
            else:
                self.cloudtrail = session.client('cloudtrail', region_name=self.region)
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")

    def listen(self) -> Generator[Dict[str, Any], None, None]:
        """Generator that yields parsed CloudTrail events."""
        if self.queue_url:
            yield from self._listen_sqs()
        else:
            yield from self._listen_cloudtrail()

    def _listen_sqs(self) -> Generator[Dict[str, Any], None, None]:
        """Polls SQS for EventBridge events with sub-second latency."""
        if not self.sqs:
            self.console.print("[red]Error: SQS client not initialized.[/red]")
            return

        self.console.print(f"[bold cyan]⚡ Monitoring Sub-Second EventBridge Events on SQS: {self.queue_url}[/bold cyan]")
        
        while True:
            try:
                response = self.sqs.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=20  # Long polling for instant delivery
                )
                
                if 'Messages' in response:
                    for message in response['Messages']:
                        try:
                            body = json.loads(message['Body'])
                            # EventBridge wraps the CloudTrail event in 'detail'
                            event = body.get('detail', body)
                            parsed = self._parse_event(event)
                            if parsed:
                                yield parsed
                        except json.JSONDecodeError:
                            pass
                        finally:
                            # Delete message from queue
                            self.sqs.delete_message(
                                QueueUrl=self.queue_url,
                                ReceiptHandle=message['ReceiptHandle']
                            )
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error polling SQS: {e}")
                time.sleep(5)

    def _listen_cloudtrail(self) -> Generator[Dict[str, Any], None, None]:
        """Polls CloudTrail API directly. Has 3-15 minute latency."""
        if not self.cloudtrail:
            self.console.print("[red]Error: CloudTrail client not initialized. Check your AWS credentials.[/red]")
            return

        self.console.print(f"[bold cyan]🎧 Monitoring Real-Time AWS CloudTrail Events (Region: {self.region})[/bold cyan]")
        
        # We cannot advance StartTime to "now" because CloudTrail events can be delayed up to 15 minutes.
        # If we advance StartTime, we will miss events that occurred 10 minutes ago but just appeared.
        # Instead, we will always look back 15 minutes and rely on `seen_events` for deduplication.
        
        while True:
            try:
                self.console.print("[dim]Polling CloudTrail for new events...[/dim]", end="\r")
                
                # Look back 15 minutes to catch delayed CloudTrail delivery
                start_time = datetime.now(timezone.utc) - timedelta(minutes=15)
                
                response = self.cloudtrail.lookup_events(
                    StartTime=start_time,
                    MaxResults=50
                )
                
                events = response.get('Events', [])
                
                # Sort events chronologically to process oldest first
                events.sort(key=lambda x: x.get('EventTime', datetime.min.replace(tzinfo=timezone.utc)))

                for event in events:
                    event_id = event.get('EventId')
                    if event_id in self.seen_events:
                        continue
                        
                    self.seen_events.add(event_id)
                    
                    # Prevent memory leak by keeping seen_events manageable
                    if len(self.seen_events) > 1000:
                        self.seen_events.clear()

                    event_name = event.get('EventName', 'Unknown')
                    
                    try:
                        ct_event = json.loads(event.get('CloudTrailEvent', '{}'))
                        parsed = self._parse_event(ct_event)
                        if parsed:
                            yield parsed
                    except json.JSONDecodeError:
                        continue

                # Sleep before next poll to avoid rate limits
                time.sleep(30)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error polling CloudTrail: {e}")
                time.sleep(30)

    def _parse_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extracts actionable information from a CloudTrail event."""
        try:
            event_source = event.get("eventSource", "")
            event_name = event.get("eventName", "")
            
            # Filter out non-mutating noise even if ReadOnly=false caught it
            if event_name.startswith(("Describe", "List", "Get", "AssumeRole")):
                return None
                
            user = event.get("userIdentity", {}).get("arn", "Unknown")
            request_params = event.get("requestParameters") or {}
            
            # S3 parsing
            if event_source == "s3.amazonaws.com":
                bucket_name = request_params.get("bucketName")
                if bucket_name:
                    return {
                        "provider": "aws",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "resource_type": "s3:bucket",
                        "event_name": event_name,
                        "user": user
                    }
                        
            # EC2 / Security Group parsing
            elif event_source == "ec2.amazonaws.com":
                group_id = request_params.get("groupId")
                if group_id:
                    return {
                        "provider": "aws",
                        "resource_id": group_id,
                        "resource_type": "ec2:security_group",
                        "event_name": event_name,
                        "user": user
                    }
                            
            # IAM parsing
            elif event_source == "iam.amazonaws.com":
                return {
                    "provider": "aws",
                    "resource_id": "root",  # Mocking targeting root account
                    "resource_type": "iam:account",
                    "event_name": event_name,
                    "user": user
                }
                
        except Exception as e:
            logger.debug(f"Failed to parse event: {e}")
            
        return None
