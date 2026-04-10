# Azure Sentinel Home Lab 

# Microsoft Sentinel SOC Lab – Windows Security Monitoring & Detection

## Overview

This project demonstrates a hands-on Security Operations Center (SOC) use case by deploying a cloud-based SIEM using Microsoft Sentinel. A local Windows endpoint was onboarded via Azure Arc and Azure Monitor Agent (AMA) to enable real-time ingestion of Windows Security logs. The project focuses on log collection, analysis, detection engineering, and alert validation using real-world attack simulations.

## Architecture

* SIEM Platform: Microsoft Sentinel
* Log Storage: Log Analytics Workspace
* Endpoint Integration: Azure Arc (Hybrid Machine)
* Agent: Azure Monitor Agent (AMA)
* Data Source: Windows Security Event Logs

## Data Ingestion

A local Windows machine was onboarded to Azure Arc and connected to Microsoft Sentinel using a Data Collection Rule (DCR). Security events were collected in real time using AMA.

### Key Event IDs Monitored

* 4624 – Successful logon
* 4625 – Failed logon
* 4672 – Special privileges assigned (admin logon)
* 4688 – Process creation
* 4732 – User added to local Administrators group

## Log Analysis (KQL)

Kusto Query Language (KQL) was used to query and analyse ingested logs.

### Example Queries

**Login Activity:**

```kql
SecurityEvent
| where EventID == 4624 or EventID == 4625
```

**Privilege & Process Activity:**

```kql
SecurityEvent
| where EventID in (4672, 4688)
```


## Detection Engineering

### 1. Brute Force Detection

Detects multiple failed login attempts within a short time window.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 5
```

* Severity: High
* Frequency: Every 5 minutes
* Trigger: >5 failed logins in 5 minutes


### 2. Privilege Escalation Detection

Detects when a user is added to the local Administrators group.

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName contains "Administrators"
```

* Severity: High
* Trigger: Any match


## Attack Simulation & Validation

### Brute Force Simulation

* Locked system (Windows + L)
* Entered incorrect password multiple times
* Generated Event ID 4625
* Detection rule triggered alert and incident

### Privilege Escalation Simulation

```powershell
net user sentineltest Password123! /add
net localgroup administrators sentineltest /add
```

* Generated Event ID 4732
* Detection rule successfully triggered alert

## Results

* Successfully ingested and analysed real-time Windows Security logs
* Validated detection rules using live attack simulations
* Generated and investigated alerts and incidents in Microsoft Sentinel
* Demonstrated end-to-end SOC workflow: ingestion → detection → alerting → investigation


## Key Learnings

* Built a functional SIEM environment using Microsoft Sentinel
* Gained hands-on experience with Azure Arc and AMA
* Developed practical detection rules aligned with real-world attack scenarios
* Understood importance of log correlation, timing, and alert filtering in SOC operations


## Conclusion

This project demonstrates practical SOC analyst capabilities by implementing a full SIEM pipeline, from log ingestion to detection and incident validation. By simulating brute-force attacks and privilege escalation, and validating alerts in Microsoft Sentinel, the project reflects real-world security monitoring and threat detection workflows used in modern SOC environments.


### Simple:

This README = **production-level portfolio quality** 👍
