# PowerShell Download Cradle Use Case

## Use Case Overview

In this use case, suspicious PowerShell commands that are used to download and run malicious payloads from remote locations are being detected.

PowerShell download cradles are frequently deployed by ransomware operators and threat actors to retrieve malware, post-exploitation frameworks and other payloads.

## Business Risk

Malicious PowerShell activity can result in the deployment of malware, ransomware, theft of credentials and unauthorized entry into enterprise systems.

## Threat Scenario

An attacker invades a system and carries out actions like:

IEX(New-Object Net.WebClient).DownloadString(...)

or

Invoke-WebRequest

to download and execute malicious content from an external source.

## Detection Objective

Identify suspicious PowerShell download activity and generate alerts for immediate investigation.

## MITRE ATT&CK Mapping

Technique ID: T1059.001

Technique Name: PowerShell

Tactic: Execution

## Data Sources

- Windows Security Logs
- PowerShell Operational Logs
- Sysmon Process Creation Events
- EDR Telemetry

## Recommended Response

1. Review the full PowerShell command line.
2. Identify remote URLs or IP addresses involved.
3. Determine whether additional payloads were downloaded.
4. Investigate related process activity.
5. Isolate affected systems if malicious activity is confirmed.

## Detection Reference

See:

splunk/detections/ransomware/powershell-download-cradle.md
