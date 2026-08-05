# Threat Hunting Lab

A practical cybersecurity portfolio containing hypothesis-driven threat hunts, SIEM queries, MITRE ATT&CK mapping, investigation workflows, false-positive analysis, and detection recommendations.

## Objectives

This repository demonstrates practical capability in:

- Threat-hunt hypothesis development
- Endpoint, identity, network, and cloud-log analysis
- SIEM and XDR investigation
- MITRE ATT&CK mapping
- Detection engineering
- Incident scoping and evidence correlation
- False-positive analysis
- Hunt-to-detection conversion

## Threat Hunts

| Hunt | Data Sources | ATT&CK Techniques | Status |
|---|---|---|---|
| Suspicious PowerShell Execution | Windows, Sysmon, EDR, SIEM | T1059.001, T1027 | Completed |
| Scheduled Task Persistence | Windows, Sysmon, EDR | T1053.005 | Planned |
| Suspicious SMB Lateral Movement | Windows, Firewall, EDR | T1021.002 | Planned |
| Anomalous Microsoft 365 Sign-in | Entra ID, Microsoft 365 | T1078 | Planned |
| Command-and-Control Activity | EDR, DNS, Proxy, Firewall | T1071.001 | Planned |
| Potential Data Exfiltration | DLP, Proxy, Firewall, Endpoint | T1041 | Planned |

## Repository Structure

```text
threat-hunting-lab/
├── hunts/
│   └── suspicious-powershell-execution.md
├── queries/
│   ├── elastic/
│   ├── kql/
│   └── sigma/
├── evidence-templates/
├── README.md
└── LICENSE
