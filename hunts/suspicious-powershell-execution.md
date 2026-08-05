# Suspicious PowerShell Execution – Threat Hunting Investigation

## 1. Hunt Overview

This threat hunt identifies potentially malicious PowerShell execution involving encoded commands, suspicious download activity, unusual parent processes, obfuscated scripts, and outbound network connections.

This is a simulated investigation created using synthetic evidence for cybersecurity portfolio purposes.

## 2. Hunt Hypothesis

An attacker may use PowerShell to execute encoded or obfuscated commands, download additional payloads, bypass security controls, establish persistence, or communicate with external infrastructure.

## 3. Security Objective

Identify PowerShell activity that deviates from normal administrative behaviour and determine whether it represents:

- Legitimate administration
- Software deployment
- Security-tool activity
- User-created automation
- Malicious script execution
- Payload delivery
- Persistence or command-and-control activity

## 4. Business Risk

Malicious PowerShell activity may result in:

- Malware execution
- Credential theft
- Security-control bypass
- Persistence
- Lateral movement
- Data exfiltration
- Command-and-control communication
- Ransomware deployment

## 5. Required Telemetry

The following data sources support this hunt:

- Windows Security Event Logs
- PowerShell Operational Logs
- Sysmon
- Endpoint Detection and Response
- SIEM process events
- DNS logs
- Proxy logs
- Firewall logs
- File-creation events
- Threat-intelligence sources

## 6. Important Event IDs

| Event ID | Source | Purpose |
|---|---|---|
| 4688 | Windows Security | New process creation |
| 4103 | PowerShell | Module logging |
| 4104 | PowerShell | Script-block logging |
| 1 | Sysmon | Process creation |
| 3 | Sysmon | Network connection |
| 11 | Sysmon | File creation |
| 13 | Sysmon | Registry value modification |

## 7. MITRE ATT&CK Mapping

| Technique | Technique ID |
|---|---|
| PowerShell | T1059.001 |
| Obfuscated or Compressed Files and Information | T1027 |
| Ingress Tool Transfer | T1105 |
| Command and Scripting Interpreter | T1059 |
| Application Layer Protocol: Web Protocols | T1071.001 |

## 8. Suspicious Behaviour Indicators

The following behaviours should be reviewed:

- PowerShell launched by Microsoft Word, Excel, Outlook, or a browser
- Use of `-EncodedCommand`, `-enc`, or Base64 strings
- Use of hidden or bypass execution options
- Download activity using `Invoke-WebRequest`
- Use of `DownloadString` or `WebClient`
- Use of `Invoke-Expression` or `IEX`
- PowerShell connecting to an external IP address
- PowerShell writing executables or scripts into temporary directories
- Execution from unusual user profiles
- PowerShell running under unexpected service accounts

## 9. Elastic EQL Hunting Query

```eql
process
where host.os.type == "windows"
  and event.type == "start"
  and process.name : ("powershell.exe", "pwsh.exe")
  and process.command_line : (
    "*-enc*",
    "*EncodedCommand*",
    "*FromBase64String*",
    "*DownloadString*",
    "*Invoke-WebRequest*",
    "*IEX*",
    "*ExecutionPolicy Bypass*",
    "*WindowStyle Hidden*"
  )
```
## 10. Microsoft Sentinel KQL Query

DeviceProcessEvents
```| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc",
    "EncodedCommand",
    "FromBase64String",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "ExecutionPolicy Bypass",
    "WindowStyle Hidden"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine,
    SHA256
| order by Timestamp desc
```

## 11. Simulated Investigation Scenario

The following synthetic event was identified:
Timestamp: 2026-08-01 10:42:17 UTC
Hostname: LAB-WKS-017
Username: test.user
Parent Process: WINWORD.EXE
Child Process: powershell.exe
Command Line: powershell.exe -WindowStyle Hidden -EncodedCommand <REDACTED>
Destination IP: 192.0.2.45
Destination Port: 443
The IP address 192.0.2.45 belongs to a documentation-only address range and does not represent a real system.

## 12. Investigation Workflow

Step 1: Validate the process chain

Review: 
```
WINWORD.EXE
└── powershell.exe
```
Microsoft Word spawning PowerShell is unusual and may indicate malicious document execution.

Step 2: Review the command line

Check for:

Encoded commands
Obfuscation
Hidden-window execution
Execution-policy bypass
Download commands
External URLs
Temporary file paths
Step 3: Decode encoded content safely

Decode the Base64 string in an isolated analysis environment.

Do not execute decoded content on a production system.

Step 4: Review PowerShell logs

Examine Event IDs:

4103
4104

Identify the actual commands, functions, URLs, file paths, and registry changes.

Step 5: Examine network activity

Correlate the PowerShell process with:

DNS queries
Proxy activity
Firewall connections
EDR network events
Threat-intelligence information
Step 6: Review file activity

Identify files created or modified by PowerShell, particularly in:
```
C:\Users\<user>\AppData\
C:\Windows\Temp\
C:\ProgramData\
C:\Users\Public\
```
Step 7: Determine scope

Search for:

The same command line on other systems
The same file hash
The same destination IP or domain
The same parent-child process relationship
The same affected user account
Related email-delivery activity

Step 8: Review persistence indicators

Check:

Scheduled tasks
Registry Run keys
Startup folders
Services
WMI subscriptions
PowerShell profiles

## 13. Evidence Assessment

| Evidence                            | Assessment                      |
| ----------------------------------- | ------------------------------- |
| Word spawning PowerShell            | High-risk process relationship  |
| Encoded command                     | Possible obfuscation            |
| Hidden PowerShell window            | Possible defence evasion        |
| External HTTPS connection           | Requires destination validation |
| Temporary file creation             | Possible payload staging        |
| Similar activity on other endpoints | Possible wider compromise       |


## 14. Potential False Positives

Possible legitimate causes include:

Software-deployment tools
System-administration scripts
Endpoint-management platforms
Security-product automation
Approved logon scripts
IT troubleshooting activity

Validation should consider:

User role
Asset purpose
Script owner
Change record
Digital signature
Execution frequency
Historical baseline
Destination reputation

## 15. Hunt Findings

The simulated activity is considered suspicious because:

PowerShell was launched by Microsoft Word
The command was encoded
The process used hidden-window execution
An outbound connection was initiated
The behaviour was not part of an approved administrative activity

## 16. Recommended Response Actions

Isolate the affected endpoint where business impact permits
Terminate the malicious process
Preserve relevant evidence
Block confirmed malicious indicators
Reset affected credentials where compromise is suspected
Review related email-delivery activity
Search the environment for matching indicators
Remove persistence mechanisms
Perform endpoint remediation
Continue monitoring after recovery

## 17. Detection Recommendation

Create a detection for PowerShell execution where one or more of the following are present:

Office application as the parent process
Encoded or obfuscated command
Hidden-window execution
Execution-policy bypass
Download-related functions
External network connection
File creation in a temporary directory
Recommended Severity
```High```

Increase to Critical when combined with:

Confirmed malicious destination
Credential theft
Persistence
Lateral movement
Multiple affected endpoints

## 18. Conclusion

The hunt demonstrates how process telemetry, PowerShell logs, network events, file activity, and threat intelligence can be correlated to identify suspicious PowerShell execution.

The investigation also demonstrates how threat-hunting findings can be converted into a permanent detection rule.

Disclaimer

This project uses synthetic data and represents a simulated security investigation.

No confidential employer, customer, or production information is included.
