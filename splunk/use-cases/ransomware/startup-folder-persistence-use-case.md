# Startup Folder Persistence Use Case

## Use Case Overview

This use case focuses on detecting unauthorized files placed in Windows Startup folders to establish persistence. Ransomware operators may abuse Startup folders to automatically launch malicious executables or scripts whenever a user logs in.

## Business Risk

Persistence through Startup folders enables ransomware to survive system reboots, maintain long-term access, and execute malicious payloads automatically. If left undetected, attackers can repeatedly execute ransomware or supporting malware.

## Threat Scenario

An attacker copies a malicious executable or script into a Windows Startup folder after gaining access to a system. The file executes automatically during the next user logon, allowing the attacker to maintain persistence and continue ransomware operations.

## Detection Objective

Identify suspicious file creation or modification within Windows Startup folders and determine whether the activity represents unauthorized persistence.

## MITRE ATT&CK Mapping

Technique ID: T1547.001

Technique Name: Registry Run Keys / Startup Folder

Tactic: Persistence

## Data Sources

- Sysmon File Creation Logs
- Windows Security Logs
- File Integrity Monitoring
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Identify the process that created the Startup folder file.
2. Review the executable or script for malicious behavior.
3. Validate whether the file was created through legitimate software installation.
4. Remove unauthorized Startup entries.
5. Investigate the affected endpoint for additional persistence mechanisms.

## Detection Reference

See:

splunk/detections/ransomware/startup-folder-persistence-detection.md
