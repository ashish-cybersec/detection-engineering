## Overview

Detects attempts to enable Remote Desktop Protocol (RDP), which is commonly abused by ransomware operators for remote access and lateral movement.

Threat actors often enable RDP on compromised systems to facilitate remote administration, maintain persistence, and spread ransomware across the environment.

## MITRE ATT&CK

- Technique ID: T1021.001
- Technique Name: Remote Services: Remote Desktop Protocol
- Tactic: Lateral Movement

## Detection Logic

Monitor for:

- Registry modifications to enable RDP
- Changes to fDenyTSConnections registry value
- PowerShell commands enabling RDP
- Firewall rule changes allowing RDP access

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
("fDenyTSConnections" AND "0")
OR
("Set-ItemProperty" AND "Terminal Server")
OR
("Remote Desktop")
```

## Potential False Positives

- Legitimate administrative activities
- IT support enabling RDP for troubleshooting
- System provisioning activities

## Investigation Steps

1. Identify who enabled RDP.
2. Review the affected host and associated user account.
3. Determine whether RDP was previously disabled.
4. Investigate related authentication events.
5. Review surrounding activity for signs of lateral movement.

## Severity

Medium

## Detection Value

Unauthorized RDP enablement is frequently associated with ransomware operations and may indicate attempts to establish remote access or move laterally.
