# WBAdmin Delete Catalog Use Case

## Use Case Overview
In this use case, the alert is triggered when the Windows Backup Catalog information is being deleted via WBAdmin commands.

Threat actors and ransomware operators can delete backup catalog data to make recovery more difficult and maximize the operational impact.

## Business Risk
Removing backup catalog data can make recovery more complicated and make backups less useful in a ransomware attack.

## Threat Scenario
An attacker gains access to a Windows system and executes:

wbadmin delete catalog -quiet

To remove back-up catalog information prior to deployment of ransomware.

## Detection Objective
Identify execution of WBAdmin commands associated with backup catalog deletion and generate alerts for immediate investigation.

## MITRE ATT&CK Mapping

Technique ID: T1490

Technique Name: Inhibit System Recovery

Tactic: Impact

## Data Sources

- Windows Security Logs
- Sysmon Process Creation Events
- EDR Telemetry

## Recommended Response
1. Identify the user executing the command.
2. Review parent process activity.
3. Verify backup availability.
4. Investigate for ransomware indicators.
5. Escalate if unauthorized activity is confirmed.

## Detection Reference

See:

splunk/detections/ransomware/wbadmin-delete-catalog.md


