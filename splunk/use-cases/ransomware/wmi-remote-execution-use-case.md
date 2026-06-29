# WMI Remote Execution Use Case

## Use Case Overview

This use case focuses on detecting Windows Management Instrumentation (WMI) remote execution activities that may indicate ransomware-related lateral movement or remote code execution.

Ransomware operators frequently abuse WMI to remotely execute commands and spread malware across enterprise environments.

## Business Risk

Unauthorized WMI execution can enable attackers to move laterally, deploy ransomware, and compromise critical business systems.

## Threat Scenario

An attacker gains access to an internal system and uses WMI to remotely execute malicious commands or ransomware payloads on additional hosts.

## Detection Objective

Identify suspicious or unauthorized WMI remote execution activity and determine whether it is associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1047

Technique Name: Windows Management Instrumentation

Tactic: Execution, Lateral Movement

## Data Sources

- Windows Security Logs
- Sysmon Logs
- WMI Activity Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Identify the user account initiating WMI execution.
2. Determine the source and destination systems.
3. Review executed commands for malicious behavior.
4. Validate whether the activity was authorized.
5. Investigate for additional lateral movement and ransomware activity.

## Detection Reference

See:

splunk/detections/ransomware/wmi-remote-execution-detection.md
