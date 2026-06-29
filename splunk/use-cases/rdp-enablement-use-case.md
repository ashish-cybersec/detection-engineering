# RDP Enablement Use Case

## Use Case Overview

This use case focuses on detecting unauthorized Remote Desktop Protocol (RDP) enablement activities that may indicate ransomware-related lateral movement or persistence.

Threat actors frequently enable RDP on compromised systems to gain remote access, move laterally, and deploy ransomware across an environment.

## Business Risk

Unauthorized RDP enablement can provide attackers with remote access to critical systems, facilitate lateral movement, and increase the risk of widespread ransomware deployment.

## Threat Scenario

An attacker modifies registry settings or system configurations to enable RDP access on a compromised endpoint and subsequently uses RDP to move laterally or maintain persistence.

## Detection Objective

Identify systems where RDP has been enabled and investigate whether the activity is legitimate or associated with malicious behavior.

## MITRE ATT&CK Mapping

Technique ID: T1021.001

Technique Name: Remote Services: Remote Desktop Protocol

Tactic: Lateral Movement

## Data Sources

- Windows Security Logs
- Sysmon Logs
- Windows Registry Auditing Logs
- Endpoint Detection and Response (EDR) Logs

## Recommended Response

1. Determine who enabled RDP.
2. Review related authentication activity.
3. Investigate associated user accounts and source systems.
4. Confirm whether RDP enablement was authorized.
5. Disable unauthorized RDP access and investigate for additional compromise.

## Detection Reference

See:

splunk/detections/ransomware/rdp-enablement-detection.md
