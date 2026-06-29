# Registry Run Key Persistence Use Case

## Use Case Overview

This use case focuses on detecting Registry Run Key modifications that may indicate ransomware-related persistence activity.

Ransomware operators frequently abuse Registry Run Keys to ensure malicious payloads execute automatically after system reboot or user logon.

## Business Risk

Unauthorized Registry Run Key modifications can enable malware persistence, allowing ransomware to survive system restarts and maintain long-term access.

## Threat Scenario

An attacker gains access to a system and modifies Registry Run Keys to automatically execute ransomware or malware whenever a user logs on.

## Detection Objective

Identify suspicious or unauthorized Registry Run Key modifications and determine whether they are associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1547.001

Technique Name: Registry Run Keys / Startup Folder

Tactic: Persistence, Privilege Escalation

## Data Sources

- Windows Security Logs
- Sysmon Logs
- Windows Registry Auditing Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Identify the user account responsible for the registry modification.
2. Review the executable configured for automatic execution.
3. Validate whether the change was authorized.
4. Analyze the executable for malicious behavior.
5. Investigate the system for additional persistence mechanisms.

## Detection Reference

See:

splunk/detections/ransomware/registry-runkey-persistence-detection.md
