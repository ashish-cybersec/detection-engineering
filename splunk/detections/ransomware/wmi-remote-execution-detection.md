# WMI Remote Execution Detection

## Overview

Detects the use of Windows Management Instrumentation (WMI) for remote process execution, a technique frequently abused by ransomware operators for lateral movement and remote code execution.

## MITRE ATT&CK

* Technique ID: T1047
* Technique Name: Windows Management Instrumentation
* Tactic: Execution, Lateral Movement

## Detection Logic

Monitor for:

* Execution of `wmic.exe`
* Remote process creation via WMI
* Suspicious command execution through WMI
* WMI spawning PowerShell, cmd.exe, or ransomware payloads

Common attacker examples:

* `wmic /node:TARGET process call create "cmd.exe /c ransomware.exe"`
* `wmic /node:TARGET process call create "powershell.exe -enc <payload>"`

## Splunk SPL Query

```spl
index=windows (Image="*\\wmic.exe" OR CommandLine="*process call create*")
| stats count by _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

## Potential False Positives

* Legitimate administrative use of WMI.
* Remote software deployment and inventory tools.
* Authorized IT automation activities.

## Investigation Steps

1. Identify the user account initiating WMI execution.
2. Review the source and target systems involved.
3. Examine the executed command for malicious behavior.
4. Validate whether the activity was authorized.
5. Investigate related lateral movement activity.

## Severity

High

## References

* https://attack.mitre.org/techniques/T1047/
* https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
