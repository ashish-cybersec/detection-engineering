# PowerShell Download Cradle Detection

## Overview

Identifies suspicious PowerShell commands often used to download and run malicious payloads.

PowerShell download cradles are often used by threat actors to obtain malware, ransomware, and post-exploitation tools from a remote location.

## MITRE ATT&CK

- Technique ID: T1059.001
- Technique Name: PowerShell
- Tactic: Execution

## Detection Logic

Monitor for PowerShell execution containing:

- IEX (Invoke-Expression)
- DownloadString
- Invoke-WebRequest
- Net.WebClient
- Encoded PowerShell commands
- Payload execution based on Base64 encoding.

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
("powershell.exe" AND "DownloadString")
OR
("powershell.exe" AND "Invoke-WebRequest")
OR
("powershell.exe" AND "Net.WebClient")
OR
("powershell.exe" AND "-enc")
```

## Potential False Positives

- Administrative automation scripts
- Software deployment tools
- PowerShell administration activities that are legitimate

## Investigation Steps

1. Review the entire PowerShell command line.
2. Identify the source URL/remote host.
3. Identify if extra payloads were downloaded.
4. Check parent process activity.
5. Investigate for lateral movement or ransomware indicators.

## Severity

High

## Detection Value
This detection provides visibility for malicious PowerShell activity, often seen in ransomware delivery and post-exploitation.

