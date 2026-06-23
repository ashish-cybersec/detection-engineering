# Encoded PowerShell Detection Use Case

## Use Case Overview

This use case focuses on detecting PowerShell executions that use encoded or Base64-encoded commands.

Threat actors frequently use encoded PowerShell commands to obfuscate malicious activity, evade security controls, and execute ransomware payloads.

## Business Risk

PowerShell encoded execution may be a sign of malware delivery, ransomware installation, evasion of defenses and unauthorized remotely executed activities.

## Threat Scenario

An attacker executes:

powershell.exe -enc <Base64Payload>

or

powershell.exe -EncodedCommand <Base64Payload>

to obscure malicious activity from administrators and security tools.

## Detection Objective

Identify and investigate suspicious encoded PowerShell executions to detect malicious activity at an early stage.

## MITRE ATT&CK Mapping

Technique ID: T1059.001

Technique Name: PowerShell

Tactic: Execution

## Data Sources

- Windows Security Logs
- PowerShell Operational Logs
- Sysmon Process Creation Events
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Decode the PowerShell command.
2. Review the parent and child processes.
3. Determine whether malware was downloaded or executed.
4. Investigate associated network connections.
5. Isolate affected systems if malicious behavior is confirmed.

## Detection Reference

See:

splunk/detections/ransomware/encoded-powershell-detection.md
