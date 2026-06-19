# WBAdmin Delete Catalog Detection

## Overview
Checks for Windows Backup Administrator commands that delete backup catalog information.

Threat actors and ransomware operators may attempt to remove backup catalogs to make recovery more difficult and to make the attack more effective.

## MITRE ATT&CK

- Technique ID: T1490
- Technique Name: Inhibit System Recovery
- Tactic: Impact

## Detection Logic

Monitor for execution of:

- wbadmin delete catalog
- wbadmin delete catalog -quiet

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
"wbadmin" AND "delete" AND "catalog"
```

## Potential False Positives

- Backup administrators performing maintenance
- Disaster recovery testing activities
- Authorized backup configuration changes

## Investigation Steps

1. Identify the user executing the command.
2. Review parent process activity.
3. Check for additional recovery-inhibition techniques.
4. Investigate for ransomware indicators.
5. Check the backup integrity and availability.
   
## Severity

High

## Detection Value

This detection is useful in identifying the attempts to remove backup recovery mechanisms that are often targeted in ransomware operations.
