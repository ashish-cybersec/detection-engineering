# Shadow Copy Deletion Detection

## Overview

Detects attempts to delete Windows Shadow Copies using utilities commonly abused by ransomware operators to inhibit system recovery.

## MITRE ATT&CK

* Technique ID: T1490
* Technique Name: Inhibit System Recovery
* Tactic: Impact

## Detection Logic

Monitor for execution of:

* `vssadmin.exe Delete Shadows /All /Quiet`
* `wmic shadowcopy delete`

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog:Security
("vssadmin.exe" AND "Delete Shadows")
OR
("wmic" AND "shadowcopy" AND "delete")
```

## Potential False Positives

* Legitimate system administration activities
* Backup software maintenance tasks

## Investigation Steps

1. Identify the user account executing the command.
2. Determine the parent process responsible for execution.
3. Review recent suspicious activity from the endpoint.
4. Investigate for signs of ransomware execution.

## Severity

High
