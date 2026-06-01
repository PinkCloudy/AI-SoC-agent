# Autonomous AI SOC Agent 🛡️🤖

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-EC2-orange.svg)](https://aws.amazon.com/)
[![Security](https://img.shields.io/badge/Security-iptables%20%7C%20Suricata-red.svg)]()

A fully autonomous Security Operations Center (SOC) Agent designed to monitor network traffic, analyze potential threats using Machine Learning & LLMs, and automatically execute kernel-level remediations (`iptables`) in real-time.

## 🎯 Project Objective
The primary goal of this project is to automate the detection and response pipeline for network threats, significantly reducing "alert fatigue" for human SOC analysts and providing zero-day defense capabilities at the edge/cloud level.

## 🏗️ System Architecture & Defense Flow

The system employs a Defense-in-Depth strategy with a 3-layer architecture:
1. **Layer 1 (Detection):** Suricata IDS/IPS for high-speed packet monitoring.
2. **Layer 2 (Analysis):** Deep contextual analysis combining NSL-KDD trained Anomaly Detection and OpenAI GPT-4 to filter False Positives.
3. **Layer 3 (Remediation):** SOAR agent autonomously generating and inserting `iptables` drop rules directly into the Linux Kernel.

```mermaid
graph TD
    Attacker((Attacker)) -.->|Malicious Payload<br>HTTP GET /?test=hacker| Nginx[Web Server Nginx]
    Attacker -->|Traffic passes Firewall| Firewall[iptables / Linux Kernel]
    Firewall --> Nginx

    Nginx -.->|Mirror Traffic| Suricata{Suricata IDS/IPS}
    Suricata -->|Rule Trigger & Log| FastLog[(Log File: fast.log)]

    subgraph AISOCAgent [AI SOC Agent - Python]
        LogMonitor[Log Monitor<br>Real-time stream]
        Whitelist{Whitelist Check<br>AWS, API IPs}
        Layer1[Layer 1: ML Model<br>NSL-KDD Anomaly]
        Layer2[Layer 2: LLM GPT-4<br>Contextual Analysis]
        Decision{Threat Assessment}
        Layer3[Layer 3: SOAR<br>Auto-Remediation]
        
        FastLog --> LogMonitor
        LogMonitor --> Whitelist
        Whitelist -->|IP in Whitelist| Ignore[Bypass]
        Whitelist -->|Not listed| Layer1
        Layer1 -->|Anomaly Detected| Layer2
        Layer2 -->|Deep Analysis| Decision
        Decision -->|False Positive| LogIgnore[Log & Ignore]
        Decision -->|Confirmed Threat| Layer3
    end

    Layer3 -->|Generate: sudo iptables -I INPUT 1...| OS_Shell[OS Command Execution]
    OS_Shell -->|Immediate Rule Update| Firewall
    Firewall -.->|Block IP - TCP Retransmission| Attacker
