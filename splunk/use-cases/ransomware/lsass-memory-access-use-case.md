# LSASS Memory Access Use Case

## Use Case Overview

This use case focuses on detecting suspicious access to LSASS memory that may indicate credential dumping activity associated with ransomware operations.

Ransomware operators commonly dump credentials from LSASS to obtain privileged accounts and facilitate lateral movement.

## Business Risk

Credential theft from LSASS can allow attackers to escalate privileges, move laterally across the environment, and deploy ransomware at scale.

## Threat Scenario

An attacker compromises a workstation and uses tools such as Mimikatz, ProcDump, or NanoDump to extract credentials from LSASS memory.

## Detection Objective

Identify unauthorized or suspicious attempts to access or dump LSASS memory and determine whether the activity is malicious.

## MITRE ATT&CK Mapping

Technique ID: T1003.001

Technique Name: LSASS Memory

Tactic: Credential Access

## Data Sources

- Windows Security Logs
- Sysmon Logs
- EDR Logs
- Process Creation Logs

## Recommended Response

1. Identify the process that accessed LSASS.
2. Determine whether the activity was authorized.
3. Investigate the associated user account.
4. Review parent and child process activity.
5. Check for signs of credential theft and lateral movement.

## Detection Reference

See:

splunk/detections/ransomware/lsass-memory-access-detection.md
