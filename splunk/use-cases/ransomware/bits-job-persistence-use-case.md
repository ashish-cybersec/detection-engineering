# BITS Job Persistence Use Case

## Use Case Overview

This use case focuses on detecting suspicious use of Windows Background Intelligent Transfer Service (BITS) jobs that may indicate ransomware persistence, payload delivery, or defense evasion.

Attackers frequently abuse BITS because it is a legitimate Windows service capable of downloading files in the background while blending in with normal system activity.

## Business Risk

Malicious BITS jobs can be used to download ransomware payloads, maintain persistence across reboots, and evade traditional detection mechanisms.

## Threat Scenario

An attacker creates a malicious BITS job using `bitsadmin.exe` or PowerShell's `Start-BitsTransfer` to retrieve ransomware components from a remote server.

## Detection Objective

Identify unauthorized or suspicious BITS job creation and determine whether it is associated with malicious payload delivery or persistence.

## MITRE ATT&CK Mapping

Technique ID: T1197

Technique Name: BITS Jobs

Tactic: Persistence, Defense Evasion

## Data Sources

- Windows Security Logs
- Sysmon Logs
- PowerShell Logs
- EDR Logs
- Process Creation Logs

## Recommended Response

1. Identify the user who created the BITS job.
2. Review the source and destination of transferred files.
3. Validate whether the download source is trusted.
4. Analyze downloaded files for malicious behavior.
5. Investigate related persistence or lateral movement activity.

## Detection Reference

See:

splunk/detections/ransomware/bits-job-persistence-detection.md
