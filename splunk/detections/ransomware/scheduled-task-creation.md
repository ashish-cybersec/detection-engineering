# Scheduled Task Creation Detection

## Overview

Detects the creation of scheduled tasks, which may be used by ransomware operators to establish persistence or execute malicious payloads.

Threat actors commonly use scheduled tasks to maintain access, launch ransomware, or execute malicious scripts at specific times.

## MITRE ATT&CK

- Technique ID: T1053.005
- Technique Name: Scheduled Task/Job: Scheduled Task
- Tactic: Persistence

## Detection Logic

Monitor for:

- schtasks.exe /create
- Register-ScheduledTask
- Creation of suspicious scheduled tasks
- Scheduled tasks executing PowerShell or scripts

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
("schtasks.exe" AND "/create")
OR
("Register-ScheduledTask")
```

## Potential False Positives

- Legitimate administrative scheduled tasks
- Software installation and update mechanisms
- Enterprise automation solutions

## Investigation Steps

1. Review the scheduled task name and configuration.
2. Determine who created the task.
3. Review the executable or script associated with the task.
4. Investigate the parent process and user account.
5. Determine whether the task is associated with malicious activity.

## Severity

Medium

## Detection Value

Scheduled task creation is a common persistence mechanism used by ransomware operators and other threat actors.
