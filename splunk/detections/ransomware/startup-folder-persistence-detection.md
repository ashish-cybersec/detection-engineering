# Startup Folder Persistence Detection

## Detection Overview

This detection identifies suspicious creation or modification of files within Windows Startup folders. Attackers commonly place executables, scripts, or shortcuts in these locations to maintain persistence and automatically execute malicious payloads when a user logs in.

## Detection Logic

Monitor file creation, modification, or movement into the following Startup directories:

- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\
- C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\

Alert when executable files, scripts, or shortcut files are added by unusual processes.

## Splunk SPL

```spl
index=sysmon EventCode=11
TargetFilename="*\\Start Menu\\Programs\\Startup\\*"
| table _time Computer User Image TargetFilename
```

## MITRE ATT&CK

Technique ID: T1547.001

Technique Name: Registry Run Keys / Startup Folder

Tactic: Persistence

## Severity

Medium

## Potential False Positives

- Software installers
- Enterprise application deployments
- Administrative scripts
- User-created startup shortcuts

## Investigation Steps

1. Identify the process that created the file.
2. Review the executable or script placed in the Startup folder.
3. Verify whether the file is digitally signed.
4. Check if similar persistence exists on other endpoints.
5. Investigate related process execution and network activity.

## Data Sources

- Sysmon File Creation Logs
- Windows Security Logs
- EDR Telemetry
- File Integrity Monitoring

## Detection References

MITRE ATT&CK T1547.001
