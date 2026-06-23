# Scheduled Task Creation Use Case

## Use Case Overview

This use case focuses on detecting the creation of scheduled tasks that may be used by ransomware operators to establish persistence or execute malicious payloads.

Threat actors commonly create scheduled tasks to maintain access, launch malware, or execute ransomware after system reboot.

## Business Risk

Malicious scheduled tasks can provide attackers with persistent access, enable ransomware execution, and allow repeated execution of malicious payloads.

## Threat Scenario

An attacker creates a scheduled task using commands such as:

schtasks.exe /create

or

Register-ScheduledTask

to execute malware or ransomware at a specified time or during system startup.

## Detection Objective

Identify suspicious scheduled task creation activities and investigate them to determine whether they are associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1053.005

Technique Name: Scheduled Task/Job: Scheduled Task

Tactic: Persistence

## Data Sources

- Windows Security Logs
- Sysmon Process Creation Events
- Task Scheduler Operational Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Review the scheduled task configuration.
2. Identify the executable or script associated with the task.
3. Determine who created the task.
4. Review the parent process and user account.
5. Disable and remove malicious tasks if confirmed.

## Detection Reference

See:

splunk/detections/ransomware/scheduled-task-creation.md
