The transition from traditional Cloud-Native Application Protection Platforms (CNAPP) to next-generation Agentic Cloud Security requires a fundamental shift in how we perceive and interact with cloud telemetry. Here is a comprehensive architectural analysis of how to bridge current gaps and build an active, autonomous cloud immune system.

### 1. The Limitations of First-Generation CNAPPs

First-generation CNAPPs were built on a paradigm of periodic visibility. They rely heavily on out-of-band snapshot scanning and API polling, running batch computations every 12 to 24 hours to generate a static inventory of misconfigurations. While this provides excellent baseline visibility, it suffers from severe architectural limitations:
  
- **The Temporal Gap:** A snapshot is a point-in-time reference. If a misconfiguration is deployed and exploited between 24-hour scan cycles, the platform is blind to the active breach.

- **Static Posture over Active Exploitability:** Legacy tools alert on theoretical exposure (e.g., an open security group) rather than active exploitation. They lack the live execution control needed to interdict an attack in progress.
### 2. The Shift to Agentic Cloud Security Platforms

To move beyond read-only dashboards, the industry is transitioning toward Agentic Cloud Security. This paradigm relies on a continuous runtime control loop defined by three stages:

- **Real-Time Sensing:** Shifting from batch API polling to event-driven streaming ingestion (e.g., routing AWS CloudTrail via EventBridge for sub-second updates).    

- **Application Runtime Protection:** Moving from mere configuration checks to monitoring active process and network behavior.    

- **Governed Intervention:** Utilizing AI agents to autonomously execute minimum-risk remediations (such as isolating an instance or reverting a security group) rather than simply opening a ticket.
### 3. The Four-Plane Context Graph

To evaluate active exploitability accurately, the platform must synthesize a graph database that merges four distinct telemetry planes:

1. **Code Provenance (ASPM):** Tracing a cloud resource back to its exact git repository, commit, and developer owner.

2. **Cloud Configuration (CSPM & CIEM):** Mapping network exposure, misconfigurations, and effective identity permissions (privilege escalation paths).

3. **Runtime Behavior (CWPP & CDR):** Overlaying live execution data, such as active network connections or spawned shells.

4. **Data Context (DSPM):** Classifying the exact sensitivity of the payload (e.g., identifying PII or PCI data).

By merging these planes into a unified Context Intelligence Graph, the engine can filter out thousands of low-risk alerts and isolate the "toxic combinations"—for example, an internet-exposed workload with a runtime vulnerability that has an IAM path to sensitive data.

### 4. Adaptive Temporal Context Windows

Streaming all telemetry constantly creates prohibitive cloud ingestion costs. The solution is an adaptive temporal context window.

Under normal conditions, the platform ingests down-sampled, aggregated metrics to maintain baseline anomaly detection. However, if the runtime sensor detects a high-severity signal (e.g., an unauthorized binary execution), the AI agent dynamically scales up the telemetry collection for that specific node. It enters a "high-resolution" recording mode, capturing deep forensic data (full network packet headers, system calls) for a limited temporal window, isolating the anomaly without permanently inflating the data ingestion bill.

### 5. Solving the In-Memory Blind Spot: Hybrid Architecture

Agentless snapshot scanning is revolutionary for its zero-friction deployment, but it possesses a critical blind spot: it reads block storage at rest. It is completely blind to fileless malware, in-memory rootkits, and transient container attacks that execute in RAM and vanish before the disk is snapshotted. To bridge this gap, modern platforms deploy a hybrid architecture:

- **Out-of-band Snapshot Scanning:** Used for deep, continuous vulnerability management, secrets detection, and compliance auditing without impacting workload performance.
- 
- **In-band eBPF Sensors:** The extended Berkeley Packet Filter (eBPF) operates at the Linux kernel level, providing unparalleled visibility into application execution, system calls, and network sockets with minimal overhead. Together, they provide complete coverage of both disk and memory.
### 6. Minimum-Risk Remediation

Security engineers often suffer from "remediation paralysis"—the fear that fixing a security group or IAM role will break a production application. An agentic platform overcomes this through deterministic safety checks:

- **Dry-Run Simulations:** Before recommending the closure of a network port, the engine queries the last 30 days of VPC Flow Logs. It mathematically proves to the developer that zero legitimate application traffic utilized that port, guaranteeing the fix is safe.

- **IaC Pull Requests:** Instead of generating IT tickets, the platform traces the misconfiguration back to the source code plane and automatically generates a Pull Request (e.g., Terraform or AWS CDK) with the exact code required to patch the flaw, bridging the gap between SecOps and DevOps.
### 7. Bridging the API Security Gap

APIs are the primary attack vector for modern cloud-native applications, specifically concerning logic flaws like Broken Object Level Authorization (BOLA). Standard CSPMs and Web Application Firewalls (WAFs) cannot detect BOLA because the API requests often look structurally legitimate and carry valid authentication tokens. eBPF bridges this gap by observing API traffic directly inside the kernel, pre-encryption or post-decryption. By tracing the function-level activity and correlating the requested object ID against the authenticated user's actual permissions, an eBPF-powered CNAPP can detect and interdict BOLA attacks and business logic abuse dynamically at runtime.
### 8. Satisfying Indian Regulatory Frameworks

Enterprise platforms operating in India face stringent regional governance that legacy, static tools struggle to satisfy:

- **DPDP Act (Digital Personal Data Protection):** Mandates strict purpose limitation, data minimization, and immediate breach notification regarding the data of Indian citizens. The inclusion of the **Data Context (DSPM) plane** ensures the platform automatically maps where PII resides, tracking data lineage and exposure in real-time to satisfy DPDP auditing.

- **CERT-In Directives:** Require organizations to report severe cyber incidents within 6 hours and maintain secure logs for 180 days. A real-time, event-driven architecture guarantees that detection occurs instantly, while the adaptive telemetry window automatically secures the necessary forensic logs for incident reporting, ensuring compliance inherently rather than as an afterthought.

![[ASPM.drawio.png]]

| **Capability**      | **Legacy Approach**  | **Next-Gen Architecture**          |
| ------------------- | -------------------- | ---------------------------------- |
| Data Collection     | 24-Hour API Polling  | Event-Driven Streaming             |
| Vulnerability Focus | Disk-Based Snapshots | Hybrid (Snapshots + eBPF Runtime)  |
| API Defense         | Perimeter WAF        | Kernel-Level eBPF BOLA Detection   |
| Remediation         | Alerting / Ticketing | Dry-Run Verified IaC Pull Requests |
![[ASPM.drawio 1.png]]

#### 1. Continuous & Adaptive Sensing (The Telemetry Layer)

Instead of waiting for a 24-hour batch scan, the platform ingests telemetry continuously across three channels:

- **Agentless Block Storage:** Out-of-band snapshot technology (SideScanning) continuously maps at-rest vulnerabilities, compliance posture, and secrets without touching the live workloads.

- **Real-Time Control Plane:** EventBridge streams live AWS IAM and configuration changes.

- **In-Band eBPF Sensors:** Sitting at the Linux kernel level, eBPF monitors encrypted API traffic, syscalls, and network sockets with near-zero overhead. eBPF provides deep API visibility, enabling the platform to detect function-level threats like Broken Object Level Authorization (BOLA) that traditional WAFs and static scanners miss completely.
#### 2. The 4-Plane Context Intelligence Graph (The Brain)

When the eBPF sensor flags anomalous API behavior, it does not immediately wake up the SOC. Instead, the signal is fed into the **Context Intelligence Graph**, which correlates signals across four planes to reveal "toxic combinations":

1. **Runtime:** eBPF sees an anomalous API request accessing an unowned object ID (BOLA).

2. **Configuration (CIEM):** The graph recognizes the container running this API assumes a highly privileged IAM role.

3. **Data (DSPM):** The graph confirms that the IAM role has access to an S3 bucket containing sensitive customer PII.

4. **Code (ASPM):** The graph traces the API deployment back to a specific GitHub repository and developer owner.

#### 3. Agentic AI Evaluation & Dry-Run (The Decision)

Legacy tools would dump all four of these facts as separate alerts into the SIEM, forcing the SOC to manually connect the dots.

Instead, the **Agentic AI Orchestrator** autonomously evaluates the incident. It decides that the active BOLA attack combined with PII access represents a critical, active exploit. Before acting, the AI proposes a minimum-risk remediation—such as modifying the container's security group to block the attacker's IP or stripping the specific S3 read permission from the IAM role. It feeds this proposed fix into the **Dry-Run Simulation Engine**, checking historical VPC flow logs and IAM access analyzer data to guarantee the fix will not break legitimate production traffic.

#### 4. Active Interdiction & SOC Handoff (The Response)

With the blast radius confirmed and the remediation verified as safe, the Agentic platform splits its response:

- **Shift-Right (Runtime Defense):** The AI commands the eBPF sensor to dynamically drop the malicious API requests at the kernel level, halting data exfiltration instantly without taking the application offline.

- **SOC Enrichment:** The platform sends a single, highly enriched incident to the SOC's SIEM/SOAR. The payload includes the full attack path, the exact data at risk, the simulated impact of the attack, and the automated steps already taken to contain it. The SOC analyst acts as an approver rather than a manual investigator.

#### 5. Code-to-Cloud Self-Healing (The Resolution)

To ensure the vulnerability does not return on the next deployment, the Agentic AI reaches back into the software development lifecycle (SDLC). Using the code provenance data, it autonomously generates a Pull Request in the originating GitHub repository containing the exact code required to patch the API logic flaw or restrict the Terraform IAM policy.

By operating a continuous runtime control loop, this architecture transforms the CNAPP from a noisy reporting tool into a self-healing ecosystem that actively defends the cloud and drastically reduces the operational burden on the SOC.


### Phase 1: Deploy the Local AI Sandbox (The Brains)

You cannot send your customer's graph data to OpenAI. We will use the **Qwen2.5-Coder** model you trained via Unsloth, running inside an Ollama container in your `ap-south-1` VPC.

1. **Deploy Ollama Sidecar:** In your ECS cluster, deploy an Ollama container running your `.gguf` model right next to your Python/Go backend.
    
2. **The Output Contract:** You must enforce JSON-only outputs from the LLM. Ollama and Qwen support strict JSON mode. The AI must return exactly this schema:
    
    JSON
    
    ```
    {
      "confidence_score": 95,
      "verdict": "TRUE_POSITIVE",
      "proposed_action": "REVOKE_IAM_ROLE",
      "target_arn": "arn:aws:iam::123:role/compromised-role",
      "rationale": "High volume S3 reads combined with unusual external IP."
    }
    ```
    

### Phase 2: The Multi-Agent Code (Python/Go Integration)

Instead of hardcoding a complex agent framework like LangChain (which is too slow), write a clean, two-step API sequence in your Python backend after the Go engine spits out a `High` or `Critical` issue.

Python

```
import requests
import json

OLLAMA_URL = "http://localhost:11434/api/chat"

def run_agentic_triage(issue, graph_context, code_context):
    # 1. The Investigator Prompt
    investigator_prompt = f"""
    You are a Cloud Security Investigator. Analyze this CNAPP Issue: {issue}
    Here is the Graph Context: {graph_context}
    Provide your verdict, confidence (0-100), and a proposed JSON remediation payload.
    """
    inv_response = requests.post(OLLAMA_URL, json={"model": "odineyes-copilot", "messages": [{"role": "user", "content": investigator_prompt}]}).json()
    hypothesis = json.loads(inv_response["message"]["content"])

    # 2. The Evaluator Prompt
    evaluator_prompt = f"""
    You are a Security Skeptic. The Investigator claims this is a {hypothesis['verdict']} with {hypothesis['confidence_score']}% confidence.
    Look at the recent GitOps deployment logs: {code_context}. 
    Does this code deployment explain the behavior? Recalculate the confidence score and output the final JSON payload.
    """
    eval_response = requests.post(OLLAMA_URL, json={"model": "odineyes-copilot", "messages": [{"role": "user", "content": evaluator_prompt}]}).json()
    final_verdict = json.loads(eval_response["message"]["content"])

    return final_verdict
```

### Phase 3: The Deterministic Guardrail (Integrating OPA)

Before your Python backend executes the AI's `proposed_action`, it **must** pass through Open Policy Agent (OPA).

1. **Write the Safety Policy (`safety.rego`):**
    
    Code snippet
    
    ```
    package odineyes.safety
    
    import rego.v1
    
    # Block autonomous destructive actions on Prod
    deny contains msg if {
        input.proposed_action == "REVOKE_IAM_ROLE"
        input.tags.Environment == "Prod"
        msg := "Autonomous IAM revocation is forbidden on Production workloads."
    }
    ```
    
2. **Evaluate in Python:**
    
    Python
    
    ```
    # Check OPA before executing
    opa_result = requests.post("http://localhost:8181/v1/data/odineyes/safety", json={"input": final_verdict})
    
    is_safe = len(opa_result.json().get("result", {}).get("deny", [])) == 0
    ```
    

### Phase 4: Tiered Enforcement Routing

Now, your Python orchestrator routes the final action based on the AI's confidence and OPA's safety check.

Python

```
def enforce(final_verdict, is_safe):
    confidence = final_verdict["confidence_score"]

    # Level 3: Auto-Resolve False Positives
    if confidence < 40:
        close_ticket_in_siem(final_verdict["rationale"])
        return "Auto-Resolved"

    # Level 3: Safe Auto-Remediation (High confidence + OPA Approved)
    if confidence >= 90 and is_safe:
        execute_aws_api_call(final_verdict["proposed_action"], final_verdict["target_arn"])
        return "Auto-Remediated"

    # Level 2: Human-in-the-Loop (High confidence BUT blocked by OPA Prod Guardrail)
    if confidence >= 90 and not is_safe:
        send_slack_interactive_webhook(final_verdict)
        return "Pending Human Approval"

    # Level 1: Escalate Novel Threat
    escalate_to_tier3_hunter(final_verdict)
    return "Escalated"
```

### How to Roll This Out Safely

Do not turn on "Level 3: Safe Auto-Remediation" on Day 1.

**Run the Agent in "Shadow Mode" for 30 days:**

1. Wire up the Investigator, Evaluator, and OPA engines.
    
2. Force **every** action to route to Level 1 or Level 2 (Slack/SIEM alerts).
    
3. Include the AI's `rationale` and `proposed_action` in the Slack alert, so your SOC team can see what the AI _would_ have done.
    
4. Add a thumb-up/thumb-down button in Slack.
    
5. When the SOC team gives the AI a 99% thumb-up rate over 30 days, you flip the configuration flag to enable autonomous execution for low-risk actions.
    

By inserting this logic between your Go Engine's output and the final database write, you turn a passive scanner into an autonomous immune system, completely contained within your own VPC.