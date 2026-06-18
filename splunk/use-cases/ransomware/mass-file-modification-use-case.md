This is the use case for mass file modification.

## Use Case Overview

This use case is centered on the detection of unusual file modifications, renames, or creations that might be a sign of an active ransomware encryption operation.

## Business Risk

Once ransomware is installed, it can quickly encrypt many business-critical files, resulting in disruption of operations, financial losses, and data recovery issues.

## Threat Scenario

Ransomware attacks are launched on the compromised endpoint. The malware starts encrypting files and renaming them with a ransomware extension.

This activity causes lots of file modification and file creation events to occur in a short time.

## Detection Objective

Detect hosts with unusually high file modification activity, which could signal active ransomware encryption.

## MITRE ATT&CK Mapping

Technique ID: T1486

Technique Name: Data Encrypted for Impact

Tactic: Impact

## Data Sources

- Windows Security Logs
- Sysmon File Creation Events
- EDR Telemetry
- File Integrity Monitoring Solutions

## Recommended Response

1. Identify affected endpoint.
2. Identify the process that caused the changes to a file.
3. Isolate impacted systems.
4. Assess the scope of encrypted files.
5. Investigate lateral movement activity.
6. Initiate ransomware incident response procedures.

## Detection Reference

See:

splunk/detections/ransomware/mass-file-modification.md
