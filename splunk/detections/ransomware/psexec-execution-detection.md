# PsExec Execution Detection

## Overview

Detects the execution of PsExec, a legitimate Sysinternals tool frequently abused by ransomware operators for lateral movement and remote code execution across enterprise environments.

## MITRE ATT&CK

* Technique ID: T1569.002
* Technique Name: System Services: Service Execution
* Tactic: Execution, Lateral Movement

## Detection Logic

Monitor for:

* Execution of `psexec.exe`
* Creation of the `PSEXESVC` service
* Remote command execution via PsExec
* Suspicious parent-child process relationships involving PsExec

Common attacker examples:

* `psexec.exe \\hostname cmd.exe`
* `psexec.exe \\hostname ransomware.exe`

## Splunk SPL Query

```spl
index=windows (Image="*\\psexec.exe" OR CommandLine="*psexec*")
| stats count by _time, host, user, Image, CommandLine, ParentImage
| sort - _time
```

## Potential False Positives

* Legitimate administrative activities by IT administrators.
* Remote software deployment tools using PsExec.
* Authorized troubleshooting activities.

## Investigation Steps

1. Identify the user account that executed PsExec.
2. Review the source and destination systems involved.
3. Examine command-line arguments for malicious payload execution.
4. Verify whether the activity was authorized.
5. Investigate additional lateral movement activity from the same host.

## Severity

High

## References

* https://attack.mitre.org/techniques/T1569/002/
* https://learn.microsoft.com/en-us/sysinternals/downloads/psexec
