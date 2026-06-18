# Mass File Modification Detection

## Overview

Identifies unusual file creation, modification or renaming events that could be ransomware activity.

Typically, ransomware encrypts many files in a short amount of time, causing a spike in file system activity.

## MITRE ATT&CK

* Technique ID: T1486
The technique is called Data Encrypted for Impact.
* Tactic: Impact

## Detection Logic

Monitor endpoints for:

* Many changes to the file in a short period of time
* Large numbers of file rename operations
* Ransomware typically adds unusual extensions to the files.
* Single-process high volume write activity.

## Splunk SPL Query

index=*
sourcetype=WinEventLog*
| stats count by host process_name
| where count > 100
| sort - count

## Potential False Positives

* Software deployment activities
* Large file migrations
* Backup operations
* Patch management processes

## Investigation Steps

   
1. The first step is to determine the process that is creating the file activity.
2. Check out recently created file extensions.
3. Identify if encryption is taking place.
4. Check for ransom notes on the infected system.
5. Look for lateral movement or other activity on other hosts.

## Severity

Critical

## Detection Value

This detection is aimed at the main impact stage of ransomware operations and could be an early indicator of active ransomware encryption.
