# Suspicious Service Creation Use Case

## Use Case Overview

This use case focuses on detecting suspicious Windows service creation activities that may indicate ransomware persistence or privilege escalation.

Threat actors commonly create malicious services to maintain persistence, execute malware automatically, or run ransomware with elevated privileges.

## Business Risk

Malicious service creation can provide attackers with persistent access, SYSTEM-level privileges, and the ability to execute ransomware or other malicious payloads.

## Threat Scenario

An attacker creates a Windows service using commands such as:

sc.exe create

or

New-Service

to automatically execute malware or ransomware during system startup.

## Detection Objective

Identify suspicious service creation activities and investigate them to determine whether they are associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1543.003

Technique Name: Create or Modify System Process: Windows Service

Tactic: Persistence

Tactic: Privilege Escalation

## Data Sources

- Windows Security Logs
- Sysmon Process Creation Events
- Windows System Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Review the newly created service name.
2. Identify the executable associated with the service.
3. Determine who created the service.
4. Review the parent process and user account.
5. Disable and remove malicious services if confirmed.

## Detection Reference

See:

splunk/detections/ransomware/suspicious-service-creation.md
