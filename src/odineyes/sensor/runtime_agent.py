"""
Odineyes - Runtime Sensor Daemon
A lightweight local agent that acts as a mock eBPF sensor.
It hooks into local system logs or auditd and sends real-time anomalies to the hub.
"""

import time
import random
import sys
from rich.console import Console

console = Console()

class RuntimeSensor:
    def __init__(self, hub_url: str = "sqs://odineyes-hub"):
        self.hub_url = hub_url
        self.running = False

    def start(self):
        self.console_print("[bold blue]🛡 Initializing Odineyes Runtime Sensor...[/bold blue]")
        self.console_print("[dim]Attaching to system calls and process execution events...[/dim]")
        time.sleep(1)
        self.console_print("[bold green]✓ eBPF Sensor Attached.[/bold green] Monitoring in real-time.")
        
        self.running = True
        try:
            self._monitor_loop()
        except KeyboardInterrupt:
            self.console_print("\n[yellow]Sensor detached. Shutting down.[/yellow]")
            sys.exit(0)

    def _monitor_loop(self):
        """Simulates monitoring system logs/eBPF events for malicious activity."""
        import json
        import uuid
        try:
            import boto3
            sqs = boto3.client('sqs')
        except ImportError:
            sqs = None
            self.console_print("[yellow]Me no find boto3! Cannot talk to big cloud![/yellow]")

        queue_url = self.hub_url
        if sqs and queue_url.startswith("sqs://"):
            queue_name = queue_url.replace("sqs://", "")
            try:
                queue_url = sqs.get_queue_url(QueueName=queue_name)['QueueUrl']
            except Exception as e:
                self.console_print(f"[red]Big cloud no find queue {queue_name}: {e}[/red]")
                sqs = None

        anomalies = [
            {"event": "Suspicious Process", "details": "www-data spawned /bin/bash", "severity": "CRITICAL"},
            {"event": "Network Anomaly", "details": "Container initiated outbound connection to known crypto-pool (1.2.3.4)", "severity": "HIGH"},
            {"event": "Fileless Malware", "details": "Execution from memory without backing file detected in PID 1042", "severity": "CRITICAL"},
            {"event": "Privilege Escalation", "details": "SUID binary executed in unexpected context", "severity": "HIGH"}
        ]
        
        while self.running:
            self.console_print("[dim]... auditing processes ...[/dim]", end="\r")
            time.sleep(random.uniform(3, 8))
            
            # Simulate a 30% chance of detecting an anomaly every cycle
            if random.random() < 0.3:
                anomaly = random.choice(anomalies)
                self.console_print(f"\n[bold red blink]🚨 RUNTIME ANOMALY DETECTED:[/bold red blink] {anomaly['event']}")
                self.console_print(f"   [yellow]Details:[/yellow] {anomaly['details']}")
                
                # Me smarter caveman! Me send to real cloud!
                if sqs:
                    try:
                        sqs.send_message(
                            QueueUrl=queue_url,
                            MessageBody=json.dumps(anomaly)
                        )
                        self.console_print(f"   [bold green]Unga bunga! Payload sent to AWS SQS {self.hub_url}![/bold green]\n")
                    except Exception as e:
                        self.console_print(f"   [red]Cloud angry! Failed to send payload: {e}[/red]\n")
                else:
                    self.console_print(f"   [dim]Telemetry payload fired to {self.hub_url} in 12ms (SIMULATED)...[/dim]\n")

    def console_print(self, msg: str, end: str = "\n"):
        console.print(msg, end=end)
