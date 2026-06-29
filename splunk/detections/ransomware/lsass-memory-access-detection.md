# LSASS Memory Access Detection

## Overview

Detects suspicious attempts to access or dump the memory of the Local Security Authority Subsystem Service (LSASS), which may indicate credential dumping activity associated with ransomware attacks.

## MITRE ATT&CK

* Technique ID: T1003.001
* Technique Name: LSASS Memory
* Tactic: Credential Access

## Detection Logic

Monitor for:

* Access to `lsass.exe` by unusual processes.
* Execution of tools commonly used for credential dumping.
* Creation of LSASS memory dump files.

Common attacker examples:

* `procdump.exe -ma lsass.exe lsass.dmp`
* `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump`
* `mimikatz.exe`
* `nanodump.exe`

## Splunk SPL Query

```spl
index=windows (CommandLine="*lsass*" OR TargetImage="*lsass.exe")
| stats count by _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

## Potential False Positives

* Authorized security tools.
* Legitimate forensic investigations.
* Endpoint protection products accessing LSASS.

## Investigation Steps

1. Identify the process accessing LSASS.
2. Determine whether the activity was authorized.
3. Review parent and child processes.
4. Investigate associated user accounts.
5. Check for lateral movement or additional compromise indicators.

## Severity

Critical

## References

* https://attack.mitre.org/techniques/T1003/001/
* https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
