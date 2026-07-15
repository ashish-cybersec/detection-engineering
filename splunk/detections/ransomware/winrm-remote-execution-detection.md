# WinRM Remote Execution Detection

## Detection Overview

This detection identifies suspicious use of Windows Remote Management (WinRM) for remote command execution. Attackers frequently abuse WinRM after obtaining valid credentials to move laterally across Windows environments and deploy ransomware.

## Detection Logic

Monitor WinRM service activity, PowerShell remoting sessions, and remote process execution initiated through WinRM. Alert when remote administrative actions originate from unusual hosts, non-administrative users, or outside approved maintenance windows.

## Splunk SPL

```spl
index=sysmon
(EventCode=1 OR EventCode=3)
(Image="*powershell.exe" OR Image="*wsmprovhost.exe")
| table _time Computer User Image ParentImage CommandLine
```

## MITRE ATT&CK

Technique ID: T1021.006

Technique Name: Windows Remote Management

Tactic: Lateral Movement

## Severity

High

## Potential False Positives

- System administrators performing remote management
- Automated administration tools
- Configuration management platforms
- Scheduled maintenance activities

## Investigation Steps

1. Identify the user initiating the WinRM session.
2. Determine the source and destination systems.
3. Review executed PowerShell commands.
4. Validate whether the activity was authorized.
5. Investigate related authentication and lateral movement events.

## Data Sources

- Windows Security Logs
- Sysmon Process Creation Logs
- PowerShell Operational Logs
- WinRM Operational Logs
- Endpoint Detection and Response (EDR)

## Detection References

MITRE ATT&CK T1021.006
