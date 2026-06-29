# Registry Run Key Persistence Detection

## Overview

Detects the creation or modification of Windows Registry Run Keys commonly abused by ransomware operators and malware to maintain persistence across system reboots.

## MITRE ATT&CK

* Technique ID: T1547.001
* Technique Name: Registry Run Keys / Startup Folder
* Tactic: Persistence, Privilege Escalation

## Detection Logic

Monitor for:

* Creation or modification of Registry Run Keys.
* Usage of `reg.exe` to add values under Run or RunOnce registry paths.
* Suspicious executables configured to launch automatically at logon.

Common attacker examples:

* `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /t REG_SZ /d "C:\Temp\malware.exe"`
* `reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v systemupdate /t REG_SZ /d "C:\Users\Public\payload.exe"`

Registry paths of interest:

* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

## Splunk SPL Query

```spl
index=windows (CommandLine="*CurrentVersion\\Run*" OR CommandLine="*CurrentVersion\\RunOnce*")
| stats count by _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

## Potential False Positives

* Legitimate software installations.
* Enterprise application auto-start configurations.
* Authorized administrative changes.

## Investigation Steps

1. Identify the user account that modified the registry key.
2. Review the executable configured for automatic execution.
3. Determine whether the change was authorized.
4. Analyze the executable for malicious behavior.
5. Investigate related persistence mechanisms on the host.

## Severity

High

## References

* https://attack.mitre.org/techniques/T1547/001/
* https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
