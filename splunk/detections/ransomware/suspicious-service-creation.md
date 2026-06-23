# Suspicious Service Creation Detection

## Overview

Detects the creation of suspicious Windows services that may be used by ransomware operators to establish persistence, execute malware, or escalate privileges.

Threat actors frequently create or modify Windows services to maintain long-term access and execute malicious payloads with elevated privileges.

## MITRE ATT&CK

- Technique ID: T1543.003
- Technique Name: Create or Modify System Process: Windows Service
- Tactic: Persistence
- Tactic: Privilege Escalation

## Detection Logic

Monitor for:

- sc.exe create
- New-Service
- Creation of new Windows services
- Services executing PowerShell, cmd.exe, or suspicious binaries

## Splunk SPL Query

```spl
index=* sourcetype=WinEventLog*
("sc.exe" AND "create")
OR
("New-Service")
```

## Potential False Positives

- Legitimate software installations
- Administrative service creation activities
- Enterprise management tools

## Investigation Steps

1. Review the newly created service name.
2. Identify the executable associated with the service.
3. Determine who created the service.
4. Review the parent process and user account.
5. Investigate whether the service is associated with malicious activity.

## Severity

High

## Detection Value

Service creation is a common persistence and privilege escalation technique used by ransomware operators and other threat actors.
