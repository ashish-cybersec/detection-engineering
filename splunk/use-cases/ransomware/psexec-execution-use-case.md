# PsExec Execution Use Case

## Use Case Overview

This use case focuses on detecting PsExec execution activities that may indicate ransomware-related lateral movement or remote code execution.

Ransomware operators commonly abuse PsExec to execute malicious payloads remotely and spread ransomware across enterprise environments.

## Business Risk

Unauthorized PsExec usage can enable attackers to move laterally, deploy ransomware, and compromise critical business systems.

## Threat Scenario

An attacker gains access to an internal system and uses PsExec to remotely execute ransomware or other malicious commands on additional hosts.

## Detection Objective

Identify unauthorized or suspicious PsExec execution activity and determine whether it is associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1569.002

Technique Name: System Services: Service Execution

Tactic: Execution, Lateral Movement

## Data Sources

- Windows Security Logs
- Sysmon Logs
- Windows Service Creation Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Identify the user account executing PsExec.
2. Determine the source and destination systems.
3. Review executed commands and associated processes.
4. Validate whether the activity was authorized.
5. Investigate for additional lateral movement and ransomware activity.

## Detection Reference

See:

splunk/detections/ransomware/psexec-execution-detection.md
