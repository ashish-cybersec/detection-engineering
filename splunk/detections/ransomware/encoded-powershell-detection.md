# Encoded PowerShell Detection

## Overview

Identifies PowerShell commands that are run with encoded or Base64-encoded arguments, a common technique adopted by ransomware operators and threat actors for evasion.

## MITRE ATT&CK

- Technique ID: T1059.001
- Technique Name: PowerShell
- Tactic: Execution

## Detection Logic

Monitor for PowerShell executions containing:

- -enc
- -EncodedCommand
- Base64 encoded strings

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
("powershell.exe" AND "-enc")
OR
("powershell.exe" AND "-EncodedCommand")
```

## Potential False Positives

- Administrative scripts using encoded commands
- Software deployment and automation tools

## Investigation Steps

1. Decode the PowerShell command.
2. Review the parent process.
3. Detect the downloaded/ executed payloads.
4. Investigate associated network connections.
5. Determine whether malicious activity occurred.

## Severity

High

## Detection Value

Encoded PowerShell execution is commonly associated with malware delivery, ransomware deployment, and defense evasion techniques.
