# Threat Hunt Report: 'The Broker'

**Participant:** Adrian Vergara
**Date:** January 2026

## Platforms and Languages Leveraged

**Platforms:**

* Microsoft Defender for Endpoint (MDE)
* Windows-based corporate workstations and servers (`as-pc1`, `as-pc2`, `as-srv`)

**Languages/Tools:**

* Kusto Query Language (KQL) for querying device events, file access, network connections, process telemetry, and registry modifications
* Native Windows utilities observed in the investigation:
  * `explorer.exe` – user interaction vector for initial payload execution
  * `notepad.exe` – spawned as a sacrificial process for injection
  * `certutil.exe` – used as a LOLBin to download AnyDesk
  * `wevtutil.exe` – used for log clearing
  * `schtasks.exe` – used for scheduled task persistence
  * `net.exe` – used for account activation and creation
  * `mstsc.exe` – used for successful RDP lateral movement
  * `wmic.exe` / `PsExec.exe` – used in failed lateral movement attempts
  * `reg.exe` – used for credential dumping via registry hive extraction
  * Reconnaissance tools: `whoami.exe`, `net.exe view`

---

## Scenario Overview

A routine security review of endpoint telemetry across the corporate environment surfaces an anomaly that quickly unravels into a sophisticated, multi-stage intrusion. What begins as a deceptively simple file download by an unsuspecting user sets off a chain of events that reaches deep into the network. The attacker, operating with patience and precision, establishes a foothold, pivots laterally across three systems, harvests credentials from memory and local stores, deploys persistent remote access tools, and ultimately targets sensitive financial payment data on the file server. Each step is deliberate — tools are renamed to blend in, logs are cleared to erase evidence, and accounts are created and activated to ensure continued access even if primary mechanisms are discovered. The investigation traces the full path of the intrusion, from the initial double-extension file that tricked a user into execution, all the way through to the staging of a financial document archive that was poised for exfiltration.

---

## Executive Summary

Between **January 15, 2026**, a multi-stage intrusion was detected across three corporate endpoints (`as-pc1`, `as-pc2`, `as-srv`), originating with the execution of a malicious double-extension file (`Daniel_Richardson_CV.pdf.exe`) by user `sophie.turner` on `as-pc1`. The payload established command and control communications with `cdn.cloud-endpoint.net` and spawned `notepad.exe` with an empty argument as a sacrificial process for in-memory code injection. The attacker conducted systematic reconnaissance, enumerated network shares and privileged groups, and deployed AnyDesk as a persistent remote access tool across all three hosts using `certutil.exe` as a download mechanism. Credential dumping was performed via `reg.exe`, targeting the SAM and SYSTEM registry hives, with extracted files staged in `C:\Users\Public`. Lateral movement was initially attempted using `WMIC.exe` and `PsExec.exe`, both of which failed, before succeeding via RDP using `mstsc.exe` under the account `david.mitchell`. A disabled account was reactivated using `net.exe /active:yes`, a scheduled task named `MicrosoftEdgeUpdateCheck` was created for persistence using a renamed payload (`RuntimeBroker.exe`), and a backdoor account `svc_backup` was created for future access. On the file server (`as-srv`), the sensitive financial document `BACS_Payments_Dec2025.ods` was opened for editing, and data was archived into `Shares.7z` ahead of potential exfiltration. Anti-forensics activity included clearing of Application and System event logs, and in-memory execution of `SharpChrome` via reflective loading into `notepad.exe` was captured through the `ClrUnbackedModuleLoaded` ActionType.

---

## ✅ Completed Flags

| Flag # | Section | Objective | Value |
|--------|---------|-----------|-------|
| **1** | Initial Access | Initial payload filename | `Daniel_Richardson_CV.pdf.exe` |
| **2** | Initial Access | SHA256 hash of initial payload | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| **3** | Initial Access | Parent process indicating execution method | `explorer.exe` |
| **4** | Initial Access | Suspicious child process spawned by payload | `notepad.exe` |
| **5** | Initial Access | Full command line of spawned process | `notepad.exe ""` |
| **6** | Command & Control | C2 domain used for outbound communication | `cdn.cloud-endpoint.net` |
| **7** | Command & Control | Process responsible for C2 traffic | `daniel_richardson_cv.pdf.exe` |
| **8** | Command & Control | Domain used for payload staging | `sync.cloud-endpoint.net` |
| **9** | Credential Access | Two registry hives targeted | `system, sam` |
| **10** | Credential Access | Local staging path for credential files | `C:\Users\Public` |
| **11** | Credential Access | User context for credential extraction | `sophie.turner` |
| **12** | Discovery | Command used to confirm attacker identity | `whoami.exe` |
| **13** | Discovery | Command used to enumerate network shares | `net.exe view` |
| **14** | Discovery | Privileged group that was queried | `administrators` |
| **15** | Persistence | Remote administration tool deployed | `AnyDesk` |
| **16** | Persistence | SHA256 hash of remote access tool | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` |
| **17** | Persistence | Native binary used to download the tool | `certutil.exe` |
| **18** | Persistence | Configuration file accessed after installation | `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf` |
| **19** | Persistence | Unattended access password configured | `intrud3r!` |
| **20** | Persistence | All hostnames where AnyDesk was deployed | `as-pc1, as-pc2, as-srv` |
| **21** | Lateral Movement | Two tools used in failed remote execution | `WMIC.exe, PsExec.exe` |
| **22** | Lateral Movement | Hostname targeted in failed attempts | `as-pc2` |
| **23** | Lateral Movement | Windows executable used for successful pivot | `mstsc.exe` |
| **24** | Lateral Movement | Full lateral movement path | `as-pc1 > as-pc2 > as-srv` |
| **25** | Lateral Movement | Account used for successful lateral movement | `david.mitchell` |
| **26** | Lateral Movement | net.exe parameter used to activate account | `active:yes` |
| **27** | Lateral Movement | User who performed account activation | `david.mitchell` |
| **28** | Persistence | Scheduled task name used for persistence | `MicrosoftEdgeUpdateCheck` |
| **29** | Persistence | Renamed binary used as persistence payload | `RuntimeBroker.exe` |
| **30** | Persistence | Backdoor account created for future access | `svc_backup` |
| **31** | Data Access | Sensitive document accessed on file server | `BACS_Payments_Dec2025.ods` |
| **32** | Data Access | File artifact proving document was opened for editing | `.~lock.BACS_Payments_Dec2025.ods#` |
| **33** | Data Access | Hostname that accessed the sensitive document | `as-pc2` |
| **34** | Data Access | Archive filename used for data staging | `Shares.7z` |
| **35** | Data Access | SHA256 hash of staged archive | `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048` |
| **36** | Anti-Forensics | Two event logs cleared by attacker | `Application, System` |
| **37** | Anti-Forensics | ActionType recording reflective code loading | `ClrUnbackedModuleLoaded` |
| **38** | Anti-Forensics | Credential theft tool loaded into memory | `SharpChrome` |
| **39** | Anti-Forensics | Host process used for malicious assembly injection | `notepad.exe` |

---

## Investigation Scope & Objectives

**Scope:**
The investigation focused on detecting, analyzing, and documenting a multi-stage intrusion across three corporate endpoints: `as-pc1`, `as-pc2`, and `as-srv`. Activities of interest included the initial execution of a malicious payload, command and control communications, credential harvesting from registry hives and browser memory, deployment of a persistent remote access tool, lateral movement across the environment, access to sensitive financial data on the file server, data staging and archiving, and anti-forensics activity including log clearing and in-memory reflective code loading.

**Objectives:**
1. **Identify the initial access vector** — Determine how the payload entered the environment, what file was involved, and how it was executed.
2. **Map command and control activity** — Identify the domains used for C2 communication and payload staging, and the process responsible for outbound connections.
3. **Trace credential access** — Confirm which registry hives were targeted, where extracted credentials were staged, and under which user context the activity occurred.
4. **Document discovery and reconnaissance** — Identify commands used to enumerate user identity, network shares, and privileged group membership.
5. **Map persistence mechanisms** — Track the deployment of AnyDesk across the environment, the scheduled task created for recurring execution, the renamed payload binary, and the backdoor account created for future access.
6. **Track lateral movement** — Establish the full movement path across all three hosts, identify failed and successful execution methods, and confirm the account used for successful pivoting.
7. **Identify data access and staging** — Confirm access to sensitive financial documents on the file server, verify editing intent through file artifacts, and document the archive created ahead of potential exfiltration.
8. **Capture anti-forensics activity** — Identify log clearing commands, reflective loading techniques, and in-memory credential theft tools used to evade detection.

---

## Flag 1 — Initial Vector

**Objective:** Identify the file that started the infection chain.

**What to Hunt:** Network telemetry on the initial endpoint for file download activity. Look for unusual filenames, particularly those with double extensions designed to masquerade as benign documents.

**Observation:** Querying `DeviceNetworkEvents` on `as-pc1` and filtering for rows with a non-empty `InitiatingProcessAccountDomain` revealed a file downloaded under the context of `sophie.turner`. The filename `Daniel_Richardson_CV.pdf.exe` immediately stood out — a classic double-extension technique designed to appear as a PDF resume while executing as a Windows binary.

**Answer:** `Daniel_Richardson_CV.pdf.exe`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where isnotempty(InitiatingProcessAccountDomain)
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1364" height="118" alt="Flag 1" src="https://github.com/user-attachments/assets/67f46fb7-96b1-4ca6-9c1e-434d50f81c12" />

---

## Flag 2 — Payload Hash

**Objective:** Identify the SHA256 hash of the initial payload.

**What to Hunt:** Extend the initial network telemetry query to project the SHA256 hash of the initiating process, allowing the payload to be uniquely identified and cross-referenced across the investigation.

**Observation:** Building on the Flag 1 query, projecting `InitiatingProcessSHA256` returned the hash associated with `Daniel_Richardson_CV.pdf.exe`. This hash later resurfaces in the investigation tied to the persistence payload, confirming the attacker reused the same binary under a different name.

**Answer:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where isnotempty(InitiatingProcessAccountDomain)
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
```

---

## Flag 3 — User Interaction

**Objective:** Determine how the payload was initially launched.

**What to Hunt:** Identify the parent process of the payload to determine whether it was launched by a user interaction, a script, or another process. The parent process is the most direct indicator of the execution method.

**Observation:** Projecting `InitiatingProcessParentFileName` on the same network event revealed `explorer.exe` as the parent process. This confirms the payload was launched directly by the user through Windows Explorer, consistent with a user double-clicking the file after downloading it — a standard phishing delivery technique.

**Answer:** `explorer.exe`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where isnotempty(InitiatingProcessAccountDomain)
| project TimeGenerated, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessParentFileName
```

---

## Flag 4 — Suspicious Child Process

**Objective:** Identify the legitimate Windows process spawned by the payload for further activity.

**What to Hunt:** Process creation events on `as-pc1` where `explorer.exe` is the grandparent process. Filtering out system-level noise narrows the results to user-context activity and surfaces any unusual child processes.

**Observation:** Filtering `DeviceProcessEvents` on `as-pc1` for processes where `InitiatingProcessParentFileName` is `explorer.exe` and excluding `nt authority` account domain activity surfaced `notepad.exe` as a suspicious child process. A legitimate user opening Notepad would never produce this relationship in the process tree — its presence here is a strong indicator that the attacker spawned it programmatically as a vehicle for process injection.

**Answer:** `notepad.exe`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="530" height="103" alt="Flag 4 and 5" src="https://github.com/user-attachments/assets/5d251fdf-ee4e-44dd-ac0f-24a6b4088d1c" />

---

## Flag 5 — Process Arguments

**Objective:** Identify the full command line of the suspicious child process to confirm injection intent.

**What to Hunt:** The same process creation query used for Flag 4 surfaces the full command line, which reveals the exact arguments passed to the spawned process.

**Observation:** The `ProcessCommandLine` column returned `notepad.exe ""` — an empty string argument being passed to Notepad. This pattern is never seen in legitimate user activity. The empty argument is a placeholder used by malicious loaders that spawn a sacrificial process to inject shellcode into, allowing the attacker to execute malicious code under the cover of a trusted Windows binary.

**Answer:** `notepad.exe ""`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="530" height="103" alt="Flag 4 and 5" src="https://github.com/user-attachments/assets/0f6f3afb-48b3-4ffd-aace-0476315a8e76" />

---

## Flag 6 — C2 Domain

**Objective:** Identify the domain used for command and control communication.

**What to Hunt:** Network events on `as-pc1` showing outbound connections initiated by the payload. Projecting `RemoteUrl` surfaces the domains being contacted.

**Observation:** Extending the network events query to include `RemoteUrl`, `RemoteIP`, and `RemotePort` revealed an outbound connection from `daniel_richardson_cv.pdf.exe` to `cdn.cloud-endpoint.net`. The domain is structured to mimic a legitimate content delivery network, a common technique used by threat actors to blend C2 traffic with normal web traffic.

**Answer:** `cdn.cloud-endpoint.net`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where isnotempty(InitiatingProcessAccountDomain)
| project TimeGenerated, ActionType, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="1355" height="128" alt="Flag 6" src="https://github.com/user-attachments/assets/d1385923-02eb-4fdb-adf4-f2d6a2da1849" />

---

## Flag 7 — C2 Process

**Objective:** Identify the process responsible for initiating C2 traffic.

**What to Hunt:** The same network events query used for Flag 6, focusing on the `InitiatingProcessFileName` column to confirm which process is making the outbound connection.

**Observation:** The `InitiatingProcessFileName` column confirmed that the outbound C2 connection to `cdn.cloud-endpoint.net` was initiated directly by `daniel_richardson_cv.pdf.exe`, confirming the payload itself is the C2 agent.

**Answer:** `daniel_richardson_cv.pdf.exe`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc1"
| where isnotempty(InitiatingProcessAccountDomain)
| project TimeGenerated, ActionType, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="328" height="96" alt="Flag 7" src="https://github.com/user-attachments/assets/600f1440-03cc-4199-b3fc-82b3579e514c" />

---

## Flag 8 — Staging Infrastructure

**Objective:** Identify the domain used to host and deliver additional payloads.

**What to Hunt:** Network events on `as-pc2` filtered for command lines containing HTTPS connections. During this investigation, suspicious lateral movement commands were also observed — specifically a `PsExec.exe` command connecting to `AS-PC2` using Administrator credentials — which provided the pivot point for narrowing the search to this device.

**Observation:** While reviewing network telemetry on `as-pc2`, a suspicious `PsExec.exe` command was observed establishing a remote session to the machine. Filtering network events on `as-pc2` for HTTPS-based command lines revealed an additional domain, `sync.cloud-endpoint.net`, being used as a staging server to deliver secondary payloads into the environment.

**Answer:** `sync.cloud-endpoint.net`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "as-pc2"
| where isnotempty(InitiatingProcessAccountDomain)
| where InitiatingProcessCommandLine contains "https"
| project TimeGenerated, ActionType, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="668" height="94" alt="Flag 8" src="https://github.com/user-attachments/assets/75826444-1dee-4880-96ff-7efdeb04490c" />

---

## Flag 9 — Registry Targets

**Objective:** Identify the two registry hives targeted for credential extraction.

**What to Hunt:** Process events across `as-pc1` and `as-pc2` for `reg.exe` commands targeting known credential-bearing registry hives. Filtering by known hive paths surfaces the exact commands used.

**Observation:** Querying for `reg save` commands referencing `HKLM\SAM` and `HKLM\SYSTEM` confirmed that the attacker targeted both hives. The SAM hive contains local account password hashes, while the SYSTEM hive contains the boot key required to decrypt them. Together these two hives provide everything needed to extract local credentials offline using tools such as Impacket or Mimikatz.

**Answer:** `system, sam`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-pc1")
| where ProcessCommandLine has_any (
    "reg save",
    "reg export",
    ".hive",
    "HKLM\\SAM",
    "HKLM\\SECURITY",
    "HKLM\\SYSTEM"
)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated desc
```
<img width="807" height="119" alt="Flag 9" src="https://github.com/user-attachments/assets/7761c1ed-8a13-49a5-8612-93584c97ff19" />

---

## Flag 10 — Local Staging

**Objective:** Identify where the extracted credential files were saved locally before exfiltration.

**What to Hunt:** The same registry hive query used for Flag 9 reveals the full command line used, including the destination path where the hive files were saved.

**Observation:** The command `"reg.exe" save HKLM\SYSTEM C:\Users\Public\system.hiv` confirmed the files were staged in `C:\Users\Public`. This directory is accessible by all users without elevated permissions and is a well-known staging location used by threat actors because files placed there can be accessed remotely without requiring special privileges.

**Answer:** `C:\Users\Public`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-pc1")
| where ProcessCommandLine has_any (
    "reg save",
    "reg export",
    ".hive",
    "HKLM\\SAM",
    "HKLM\\SECURITY",
    "HKLM\\SYSTEM"
)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated desc
```
<img width="293" height="99" alt="Flag 10" src="https://github.com/user-attachments/assets/ff2d639a-ffb7-466a-b997-9ea5c007462b" />

---

## Flag 11 — Execution Identity

**Objective:** Identify the user context under which credential extraction was performed.

**What to Hunt:** The same registry hive query used for Flags 9 and 10 also exposes the `AccountName` column, which reveals who executed the commands.

**Observation:** The `AccountName` column confirmed that the credential extraction commands were executed under the context of `sophie.turner` — the same account associated with the initial payload execution on `as-pc1`. This indicates the attacker maintained that user's session throughout the credential dumping phase.

**Answer:** `sophie.turner`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-pc1")
| where ProcessCommandLine has_any (
    "reg save",
    "reg export",
    ".hive",
    "HKLM\\SAM",
    "HKLM\\SECURITY",
    "HKLM\\SYSTEM"
)
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by TimeGenerated desc
```
<img width="182" height="86" alt="Flag 11" src="https://github.com/user-attachments/assets/15b88a41-3b36-42ee-a5df-5d39a4619822" />

---

## Flag 12 — User Context

**Objective:** Identify the command used by the attacker to confirm their identity after initial access.

**What to Hunt:** Process events on `as-pc1` filtered for common reconnaissance utilities. Searching for known enumeration commands surfaces the first identity confirmation action taken after the payload executed.

**Observation:** Filtering `DeviceProcessEvents` for known reconnaissance commands including `whoami`, `hostname`, `tasklist`, and `net user` revealed that `whoami.exe` was among the first commands executed after the initial payload ran. This is a standard post-exploitation step used by threat actors to confirm which user account they are operating under and what privileges they have.

**Answer:** `whoami.exe`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="563" height="101" alt="Flag 12" src="https://github.com/user-attachments/assets/77f6a92e-bcf5-4a4f-a286-a2ce7485866a" />

---

## Flag 13 — Network Enumeration

**Objective:** Identify the command used to enumerate available network shares.

**What to Hunt:** The same post-exploitation process query used for Flag 12 surfaces additional reconnaissance commands executed in the same timeframe.

**Observation:** The results of the reconnaissance query also returned `net.exe view`, a command used to list all shared resources visible on the network. This tells us the attacker was actively mapping the environment to locate file shares and other accessible resources — a key step before lateral movement and data access.

**Answer:** `net.exe view`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="616" height="215" alt="Flag 13, 14, 15,  16" src="https://github.com/user-attachments/assets/f4fb25a0-5d57-45e0-abad-2cb029a923c6" />

---

## Flag 14 — Local Admins

**Objective:** Identify the privileged local group that was enumerated by the attacker.

**What to Hunt:** The same reconnaissance query surfaces command lines referencing local group enumeration, revealing which privileged groups the attacker was interested in.

**Observation:** The command line output from the reconnaissance query revealed that the attacker queried the `administrators` group, likely to determine which accounts had local admin privileges on the machine. This is consistent with an attacker identifying potential lateral movement targets or confirming their current level of access.

**Answer:** `administrators`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="616" height="215" alt="Flag 13, 14, 15,  16" src="https://github.com/user-attachments/assets/a8548b92-a13b-48ed-b2b9-e7823a9be846" />

---

## Flag 15 — Remote Tool

**Objective:** Identify the legitimate remote administration tool deployed for persistent access.

**What to Hunt:** The same broad process query used for discovery activity also surfaces the installation of remote access tools executed within the same user session.

**Observation:** Within the same process telemetry window, `AnyDesk.exe` appeared as a process being executed on `as-pc1`. AnyDesk is a legitimate remote desktop application that is heavily abused by threat actors because it blends in with normal IT activity, uses outbound connections on commonly allowed ports, and is rarely blocked by default security controls.

**Answer:** `AnyDesk`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where InitiatingProcessParentFileName == "explorer.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated desc
```
<img width="616" height="215" alt="Flag 13, 14, 15,  16" src="https://github.com/user-attachments/assets/80678e66-6106-4ab0-a697-3995e749e67c" />

---

## Flag 16 — Remote Tool Hash

**Objective:** Identify the SHA256 hash of the AnyDesk binary deployed on the endpoint.

**What to Hunt:** Filter process events specifically for `AnyDesk.exe` and project the SHA256 hash to uniquely identify the binary. This allows it to be tracked across devices and cross-referenced with the persistence payload hash discovered later in the investigation.

**Observation:** Filtering `DeviceProcessEvents` for `AnyDesk.exe` and projecting `SHA256` returned the hash of the binary. This hash was later found to match the persistence payload `RuntimeBroker.exe`, confirming the attacker reused the same binary under a different name to evade detection.

**Answer:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where FileName == "AnyDesk.exe"
| project TimeGenerated, FileName, ProcessCommandLine, SHA256
| order by TimeGenerated desc
```
<img width="616" height="215" alt="Flag 13, 14, 15,  16" src="https://github.com/user-attachments/assets/bfac939e-965b-498f-bf07-90d9c0ca72ec" />

---

## Flag 17 — Download Method

**Objective:** Identify the native Windows binary used to download AnyDesk.

**What to Hunt:** Network events filtered by command lines referencing AnyDesk reveal how the binary was retrieved. Living-off-the-land binaries (LOLBins) are commonly used to bypass application whitelisting and reduce the need for custom tooling.

**Observation:** Filtering network events for command lines containing "AnyDesk" revealed that `certutil.exe` was used to download the AnyDesk installer. `certutil.exe` is a native Windows binary primarily used for certificate management but is heavily abused as a download tool because it is trusted by default and can retrieve files from remote URLs without triggering many security controls.

**Answer:** `certutil.exe`

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where DeviceName in ("as-pc2", "as-pc1")
| where isnotempty(InitiatingProcessAccountDomain)
| where InitiatingProcessCommandLine contains "AnyDesk"
| project TimeGenerated, ActionType, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="602" height="83" alt="Flag 17" src="https://github.com/user-attachments/assets/103237d1-9e04-44f7-95a1-7ba9fa9bc706" />

---

## Flag 18 — Configuration Access

**Objective:** Identify the AnyDesk configuration file accessed after installation.

**What to Hunt:** Process events filtered for command lines referencing configuration files reveal post-installation activity. Configuration file access after tool installation is a strong indicator that the attacker was customizing the tool for unattended remote access.

**Observation:** Filtering `DeviceProcessEvents` for command lines containing "conf" surfaced access to `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`. This is the AnyDesk configuration file that controls connection behavior, including unattended access settings. Accessing this file immediately after installation indicates the attacker was configuring AnyDesk to allow persistent, password-protected remote access without requiring user interaction.

**Answer:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where ProcessCommandLine contains "conf"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, SHA256
| order by TimeGenerated desc
```
<img width="914" height="126" alt="Flag 18" src="https://github.com/user-attachments/assets/c3d41a9e-e297-4e5c-9692-783d604a0601" />

---

## Flag 19 — Access Credentials

**Objective:** Identify the password configured for unattended AnyDesk access.

**What to Hunt:** Process events filtered for AnyDesk-related command lines reveal the exact configuration commands used, including any password values set for unattended access.

**Observation:** Filtering for AnyDesk-related process command lines returned the command used to set an unattended access password of `intrud3r!`. This confirms the attacker configured AnyDesk to allow persistent remote access without any user interaction, meaning they could reconnect to the compromised machine at any time using this password, even if the original user session was closed.

**Answer:** `intrud3r!`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName == "as-pc1"
| where AccountDomain <> "nt authority"
| where ProcessCommandLine contains "AnyDesk"
| project TimeGenerated, FileName, FolderPath, ProcessCommandLine, SHA256
| order by TimeGenerated desc
```

---

## Flag 20 — Deployment Footprint

**Objective:** Identify all hostnames where AnyDesk was deployed across the environment.

**What to Hunt:** File creation events for `AnyDesk.exe` across all devices, summarized by device name. This surfaces every machine where the binary was written to disk, revealing the full scope of the deployment.

**Observation:** Querying `DeviceFileEvents` for `AnyDesk.exe` file creation events and summarizing by `DeviceName` confirmed that AnyDesk was deployed across all three endpoints: `as-pc1` at `04:08`, `as-pc2` at `04:40`, and `as-srv` at `04:57`. The chronological order of deployment mirrors the lateral movement path, with each machine being backdoored shortly after the attacker gained access to it.

**Answer:** `as-pc1, as-pc2, as-srv`

**KQL Query Used:**
```kql
DeviceFileEvents
| where FileName =~ "AnyDesk.exe"
| where ActionType == "FileCreated"
| summarize FirstSeen = min(Timestamp) by DeviceName, FolderPath, InitiatingProcessFileName
| order by FirstSeen asc
```
<img width="522" height="132" alt="Flag 20" src="https://github.com/user-attachments/assets/b4bd2408-9fcd-4f55-b8b7-099a6e9d0cf6" />

---

## Flag 21 — Failed Execution

**Objective:** Identify the two remote execution tools that were attempted but failed.

**What to Hunt:** A broad search across all three devices targeting known remote execution binaries, filtered by command line arguments indicative of remote targeting. During the investigation, a broad search was conducted across the environment targeting known remote execution binaries commonly leveraged by threat actors during lateral movement. The query searched for process execution events where the filename matched tools such as `psexec.exe`, `wmic.exe`, `wmiexec.exe`, `schtasks.exe`, `sc.exe`, `winrs.exe`, and others. To reduce noise, the results were further filtered by command line arguments indicative of remote targeting, such as UNC paths (`\\`), `/node:` flags, `-ComputerName` parameters, and direct references to known hostnames in the environment.

**Observation:** The results surfaced both `WMIC.exe` and `PsExec.exe` being used with remote execution arguments targeting `as-pc2`. `WMIC.exe` was observed first at `04:18`, followed by `PsExec.exe` at `04:24`. Neither attempt succeeded, which prompted the attacker to pivot to a different lateral movement method.

**Answer:** `WMIC.exe, PsExec.exe`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| where FileName has_any ("psexec.exe","Wmic.exe","wmiexec.exe","schtasks.exe","at.exe","sc.exe","powershell.exe","msiexec.exe","mshta.exe","rundll32.exe","Regsvr32.exe","winrs.exe","winrm.exe")
| where ProcessCommandLine has_any ("\\\\","/node:","-ComputerName","remote","/s ","AS-PC1","AS-PC2")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1241" height="275" alt="Flag 21" src="https://github.com/user-attachments/assets/bf45d63b-9203-4a09-bf25-26b7393646f9" />

---

## Flag 22 — Target Host

**Objective:** Identify the hostname that was targeted during the failed remote execution attempts.

**What to Hunt:** The same broad lateral movement query used for Flag 21 surfaces the specific hostname referenced in the command line arguments of both failed execution attempts.

**Observation:** Both the `WMIC.exe` and `PsExec.exe` command lines included references to `as-pc2` as the target machine. This confirms that `as-pc2` was the intended next hop in the attacker's lateral movement path, and that the failed execution attempts were specifically directed at that host.

**Answer:** `as-pc2`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| where FileName has_any ("psexec.exe","Wmic.exe","wmiexec.exe","schtasks.exe","at.exe","sc.exe","powershell.exe","msiexec.exe","mshta.exe","rundll32.exe","Regsvr32.exe","winrs.exe","winrm.exe")
| where ProcessCommandLine has_any ("\\\\","/node:","-ComputerName","remote","/s ","AS-PC1","AS-PC2")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1193" height="73" alt="Flag 22" src="https://github.com/user-attachments/assets/fa7eb6de-9501-4858-918d-7d8733c47ffd" />

---

## Flag 23 — Successful Pivot

**Objective:** Identify the Windows executable used to successfully achieve lateral movement after the failed attempts.

**What to Hunt:** Device events filtered by the version info file description for Remote Desktop Connection surfaces RDP-based lateral movement activity across all three endpoints.

**Observation:** Filtering `DeviceEvents` for processes with a `InitiatingProcessVersionInfoFileDescription` of "Remote Desktop Connection" confirmed that `mstsc.exe` was used to successfully pivot to `as-pc2` and subsequently to `as-srv`. RDP via `mstsc.exe` was the attacker's fallback method after `WMIC.exe` and `PsExec.exe` failed — made possible by the valid credentials already harvested during the credential dumping phase.

**Answer:** `mstsc.exe`

**KQL Query Used:**
```kql
DeviceEvents
| where DeviceName has_any ("as-pc2", "as-pc1", "as-srv")
| where InitiatingProcessVersionInfoFileDescription == "Remote Desktop Connection"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```
<img width="848" height="248" alt="Flag 23" src="https://github.com/user-attachments/assets/4b692389-9ffc-425c-ac47-402899e6f9ce" />

---

## Flag 24 — Movement Path

**Objective:** Document the full lateral movement path taken by the attacker across the environment.

**What to Hunt:** The chronological timestamps from the RDP telemetry across all three devices establish the order in which the attacker moved through the environment.

**Observation:** RDP activity was first observed on `as-pc1` at `04:29`, then on `as-pc2` at `04:54`, and finally AnyDesk was deployed on `as-srv` at `04:57`. This confirms a clear sequential movement path originating on the initial compromise host and progressing toward the file server.

**Answer:** `as-pc1 > as-pc2 > as-srv`

---

## Flag 25 — Compromised Account

**Objective:** Identify the account used for successful lateral movement.

**What to Hunt:** Extending the RDP telemetry query to include `InitiatingProcessAccountName` reveals which account authenticated successfully during the RDP sessions.

**Observation:** Adding the `InitiatingProcessAccountName` projection to the RDP query confirmed that `david.mitchell` was the account used for successful lateral movement. This account was likely obtained during the credential dumping phase on `as-pc1`, where registry hives were extracted and staged for offline decryption.

**Answer:** `david.mitchell`

**KQL Query Used:**
```kql
DeviceEvents
| where DeviceName has_any ("as-pc2", "as-pc1", "as-srv")
| where InitiatingProcessVersionInfoFileDescription == "Remote Desktop Connection"
| project Timestamp, DeviceName, InitiatingProcessAccountName, AccountName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
<img width="510" height="239" alt="Flag 25" src="https://github.com/user-attachments/assets/ae43debc-0435-4423-99a6-0ed8993be831" />

---

## Flag 26 — Account Activation

**Objective:** Identify the net.exe parameter used to reactivate a disabled account.

**What to Hunt:** Process events across all three devices filtered for `net.exe` and `net1.exe` commands referencing account activation parameters. Searching for keywords like `active` and `yes` narrows results to account enablement activity.

**Observation:** The query returned a `net.exe` command using the `/active:yes` parameter, confirming that a previously disabled account was reactivated. This is a well-known persistence technique where threat actors enable dormant accounts to establish an additional foothold that is less likely to be noticed during incident response.

**Answer:** `active:yes`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName has_any ("as-pc2", "as-pc1", "as-srv")
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has_any ("user","active","yes","enable")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="870" height="245" alt="Flag 26, 27" src="https://github.com/user-attachments/assets/b2d66c0d-1f3a-4535-9f71-8e75dc1cc542" />

---

## Flag 27 — Activation Context

**Objective:** Identify who performed the account activation.

**What to Hunt:** The same account activation query used for Flag 26 also exposes the `AccountName` column, revealing the user context under which the activation command was run.

**Observation:** The `AccountName` column from the same query confirmed that `david.mitchell` performed the account activation. This is consistent with the attacker operating under the `david.mitchell` account following the successful RDP lateral movement, and using that access to reactivate additional accounts for redundant persistence.

**Answer:** `david.mitchell`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where DeviceName has_any ("as-pc2", "as-pc1", "as-srv")
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has_any ("user","active","yes","enable")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="870" height="245" alt="Flag 26, 27" src="https://github.com/user-attachments/assets/745338c3-dc37-4c2b-a21c-363fa496b97b" />

---

## Flag 28 — Scheduled Persistence

**Objective:** Identify the name of the scheduled task created for persistence.

**What to Hunt:** Process events filtered for `schtasks.exe` with a `/create` argument across all three devices. The task name is embedded in the command line via the `/tn` flag.

**Observation:** The query returned the full scheduled task creation command: `schtasks.exe /create /tn MicrosoftEdgeUpdateCheck /tr C:\Users\Public\RuntimeBroker.exe /sc daily /st 03:00 /rl highest`. The task was named `MicrosoftEdgeUpdateCheck` — deliberately chosen to mimic a legitimate Microsoft Edge update process and blend in with other scheduled tasks on the system.

**Answer:** `MicrosoftEdgeUpdateCheck`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1191" height="128" alt="Flag 28, 29" src="https://github.com/user-attachments/assets/3d451860-b78d-4e69-b791-5b1a2d31a035" />

---

## Flag 29 — Renamed Binary

**Objective:** Identify the filename used to disguise the persistence payload.

**What to Hunt:** The scheduled task creation command from Flag 28 reveals the binary path referenced in the `/tr` argument, which is the executable that will be run by the task.

**Observation:** The `/tr` argument in the scheduled task command pointed to `C:\Users\Public\RuntimeBroker.exe`. The real `RuntimeBroker.exe` is a legitimate Windows process that resides in `C:\Windows\System32`. Having a file with the same name in `C:\Users\Public` is a textbook masquerading technique — the attacker renamed their malicious binary after a trusted Windows process to avoid suspicion.

**Answer:** `RuntimeBroker.exe`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1191" height="128" alt="Flag 28, 29" src="https://github.com/user-attachments/assets/fdc6ec8a-868f-4013-9e14-ecb8031ad21b" />

---

## Flag 30 — Backdoor Account

**Objective:** Identify the new local account created by the attacker for future access.

**What to Hunt:** Process events filtered for `net.exe` and `net1.exe` commands referencing `/add`, which is the flag used when creating a new local user account.

**Observation:** The query returned a `net.exe` command creating a new local account named `svc_backup`. The name was chosen to blend in with legitimate service accounts, making it less likely to be flagged during a routine account audit. Combined with the account activation in Flag 26, this gives the attacker multiple redundant access paths into the environment.

**Answer:** `svc_backup`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has "user" and ProcessCommandLine has "/add"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="905" height="119" alt="Flag 30" src="https://github.com/user-attachments/assets/9eac8179-7153-4271-b555-73c75b23b791" />

---

## Flag 31 — Sensitive Document

**Objective:** Identify the sensitive document accessed on the file server.

**What to Hunt:** File events on `as-srv` filtered by folder paths associated with shared or sensitive data locations such as Finance, Payroll, and HR directories.

**Observation:** Filtering `DeviceFileEvents` on `as-srv` for activity within sensitive directory paths returned the file `BACS_Payments_Dec2025.ods`. BACS stands for Bankers Automated Clearing System — a UK bank transfer system — making this a highly sensitive financial payments document containing December 2025 payment data, including account numbers, sort codes, and payment amounts.

**Answer:** `BACS_Payments_Dec2025.ods`

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FolderPath has_any (
    "\\Share\\","\\FileServer\\","\\Shared\\","\\Documents\\",
    "\\Confidential\\","\\Sensitive\\","\\Finance\\","\\HR\\",
    "\\Legal\\","\\Payroll\\"
)
| project Timestamp, ActionType, DeviceName, FileName, FolderPath
| order by Timestamp desc
```
<img width="1102" height="169" alt="Flag 31 32" src="https://github.com/user-attachments/assets/6ca00e3a-a7d7-4413-9345-bf02197da6a8" />

---

## Flag 32 — Modification Evidence

**Objective:** Identify the file artifact that proves the document was opened for editing rather than just viewed.

**What to Hunt:** The same file events query used for Flag 31 surfaces not just the target document but also associated lock files created by the application that opened it.

**Observation:** Alongside the `.ods` file, the query returned `.~lock.BACS_Payments_Dec2025.ods#`. This is a LibreOffice lock file — automatically created whenever a file is opened in edit mode, not read-only mode. The lock file exists for the entire duration the document is open and is deleted when it is closed. Its presence in the telemetry confirms the document was actively opened for editing, not simply previewed, which elevates the severity of the data access significantly and raises the possibility of data manipulation in addition to theft.

**Answer:** `.~lock.BACS_Payments_Dec2025.ods#`

**KQL Query Used:**
```kql
DeviceFileEvents
| where DeviceName == "as-srv"
| where FolderPath has_any (
    "\\Share\\","\\FileServer\\","\\Shared\\","\\Documents\\",
    "\\Confidential\\","\\Sensitive\\","\\Finance\\","\\HR\\",
    "\\Legal\\","\\Payroll\\"
)
| project Timestamp, ActionType, DeviceName, FileName, FolderPath
| order by Timestamp desc
```
<img width="1102" height="169" alt="Flag 31 32" src="https://github.com/user-attachments/assets/57c53fa7-2ee7-4543-8d97-b4eb0abdb771" />

---

## Flag 33 — Access Origin

**Objective:** Identify which workstation accessed the sensitive document on the file server.

**What to Hunt:** File events filtered specifically for the BACS payments filename across all devices, which reveals which endpoint initiated the file access.

**Observation:** Querying for file events referencing `BACS_Payments_Dec2025` returned activity originating from `as-pc2`. This is consistent with the lateral movement path — the attacker had already pivoted to `as-pc2` via RDP under `david.mitchell` and used that machine to remotely access the financial document stored on `as-srv`.

**Answer:** `as-pc2`

**KQL Query Used:**
```kql
DeviceFileEvents
| where FileName has "BACS_Payments_Dec2025"
    or FileName has ".~lock.BACS_Payments_Dec2025"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
```
<img width="980" height="125" alt="Flag 33" src="https://github.com/user-attachments/assets/65976e56-0573-44b3-9e30-f62756dee101" />

---

## Flag 34 — Exfil Archive

**Objective:** Identify the archive file created to package data ahead of potential exfiltration.

**What to Hunt:** File creation events across all three devices filtered for common archive file extensions. Staging data in a compressed archive before exfiltration is a standard technique used to reduce transfer size and bundle multiple files into a single package.

**Observation:** The query returned `Shares.7z` as a newly created archive file. The filename suggests the attacker archived the contents of network shares, consistent with their earlier enumeration of network resources via `net.exe view`. The `.7z` format is a common choice for threat actors due to its strong compression and optional encryption capabilities.

**Answer:** `Shares.7z`

**KQL Query Used:**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar"
    or FileName endswith ".7z" or FileName endswith ".tar"
    or FileName endswith ".cab"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="998" height="175" alt="Flag 34" src="https://github.com/user-attachments/assets/9dfcc291-eeb8-48f4-b7f4-5d73b2cb564b" />

---

## Flag 35 — Archive Hash

**Objective:** Identify the SHA256 hash of the staged archive.

**What to Hunt:** The same archive file creation query used for Flag 34, extended to include the `SHA256` column. This uniquely identifies the archive and allows it to be tracked or cross-referenced in threat intelligence feeds.

**Observation:** Adding `SHA256` to the projection returned the hash of `Shares.7z`. This hash can be used to confirm the integrity of the archive, track it if it surfaces elsewhere in the environment, or submit it to threat intelligence platforms to check for prior associations with known threat actor infrastructure.

**Answer:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

**KQL Query Used:**
```kql
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar"
    or FileName endswith ".7z" or FileName endswith ".tar"
    or FileName endswith ".cab"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```
<img width="917" height="121" alt="Flag 35" src="https://github.com/user-attachments/assets/0e9a7658-d7ca-4204-9c0a-7ba6c041f616" />

---

## Flag 36 — Log Clearing

**Objective:** Identify which event logs were cleared by the attacker to cover their tracks.

**What to Hunt:** Process events filtered for `wevtutil.exe` commands referencing known event log names. Log clearing is typically one of the final steps in an intrusion, performed to remove forensic evidence and make investigation more difficult.

**Observation:** The query returned `wevtutil.exe` commands clearing the `Application` and `System` event logs. These are two of the most important Windows event logs for forensic investigation. Their deletion represents a deliberate attempt to destroy evidence of the attacker's actions before concluding the operation.

**Answer:** `Application, System`

**KQL Query Used:**
```kql
DeviceProcessEvents
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (
    "cl","clear-log","Security","System","Application",
    "PowerShell","Microsoft-Windows"
)
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="836" height="239" alt="Flag 36" src="https://github.com/user-attachments/assets/8a57d3e9-eecb-4d8a-839c-42e0682530c0" />

---

## Flag 37 — Reflective Loading

**Objective:** Identify the ActionType that recorded reflective code loading activity.

**What to Hunt:** Rather than searching for a specific ActionType, this was discovered by first enumerating all distinct ActionTypes observed across the three devices during the investigation period. This broad approach surfaces unusual ActionTypes that stand out against the expected baseline.

**Observation:** Running `distinct ActionType` across all three devices returned a list of observed event types. `ClrUnbackedModuleLoaded` immediately stood out as unusual. This ActionType is triggered when a .NET assembly is loaded directly into memory without a corresponding file on disk — the defining characteristic of reflective code loading. Its presence confirmed that the attacker was executing malicious code entirely in memory to avoid leaving artifacts on the filesystem.

**Answer:** `ClrUnbackedModuleLoaded`

**KQL Query Used:**
```kql
DeviceEvents
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| distinct ActionType
```
<img width="313" height="173" alt="Flag 37" src="https://github.com/user-attachments/assets/499287f3-a760-43a7-bb54-32131677bdd7" />

---

## Flag 38 — Memory Tool

**Objective:** Identify the credential theft tool that was loaded directly into memory.

**What to Hunt:** Device events filtered specifically for the `ClrUnbackedModuleLoaded` ActionType, projecting `AdditionalFields` and related process metadata to identify what was loaded and where.

**Observation:** Filtering for `ClrUnbackedModuleLoaded` events and projecting `AdditionalFields` confirmed that `SharpChrome` was the tool loaded into memory. SharpChrome is a .NET-based credential theft tool specifically designed to extract saved passwords, session cookies, and browsing history directly from Google Chrome and other Chromium-based browsers. Running entirely in memory, it leaves no file artifacts on disk, making it extremely difficult to detect with traditional endpoint security tools.

**Answer:** `SharpChrome`

**KQL Query Used:**
```kql
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ActionType, AdditionalFields, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```
<img width="977" height="110" alt="Flag 38 39" src="https://github.com/user-attachments/assets/f77f1b8a-74d3-4e83-8914-f69d82806122" />

---

## Flag 39 — Host Process

**Objective:** Identify the legitimate process that was used to host the malicious SharpChrome assembly.

**What to Hunt:** The same `ClrUnbackedModuleLoaded` query used for Flag 38 also surfaces the `InitiatingProcessFileName`, which reveals which process was hosting the injected assembly.

**Observation:** The `InitiatingProcessFileName` column confirmed that `notepad.exe` was the host process for the SharpChrome assembly. This connects back to Flag 4 and Flag 5, where `notepad.exe` was spawned with an empty argument as a sacrificial process. The entire purpose of that initial spawn was to create a hollow, trusted process that could be injected into — with SharpChrome being the payload ultimately loaded into its memory space.

**Answer:** `notepad.exe`

**KQL Query Used:**
```kql
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
| where DeviceName in ("as-pc2", "as-pc1", "as-srv")
| project Timestamp, DeviceName, ActionType, AdditionalFields, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
```
<img width="977" height="110" alt="Flag 38 39" src="https://github.com/user-attachments/assets/3495b677-1f52-4580-82f2-14ed485ea98d" />

---

## 🕒 Timeline of Events

### January 15, 2026 — Initial Compromise (as-pc1)

- **03:47 UTC** — User `sophie.turner` downloads and executes `Daniel_Richardson_CV.pdf.exe` via Windows Explorer on `as-pc1`, initiating the infection chain (**Flags 1, 2, 3**). The payload immediately establishes a C2 connection to `cdn.cloud-endpoint.net` (**Flag 6, 7**).
- **03:58–04:01 UTC** — Post-execution reconnaissance begins. The attacker runs `whoami.exe` to confirm user context, `net.exe view` to enumerate network shares, and queries the `administrators` group to map privileged accounts (**Flags 12, 13, 14**).
- **04:08 UTC** — AnyDesk is downloaded via `certutil.exe` from `sync.cloud-endpoint.net` and installed on `as-pc1`. The configuration file is accessed and an unattended access password of `intrud3r!` is set (**Flags 15, 16, 17, 18, 19, 20**).

### January 15, 2026 — Payload Injection & Credential Dumping (as-pc1)

- **05:09 UTC** — `notepad.exe ""` is spawned as a sacrificial process for in-memory code injection (**Flags 4, 5**). SharpChrome is reflectively loaded into `notepad.exe` memory via `ClrUnbackedModuleLoaded` to harvest browser credentials (**Flags 37, 38, 39**).
- **04:13 UTC** — Registry hive extraction begins. `reg.exe` is used to save `HKLM\SAM` and `HKLM\SYSTEM` to `C:\Users\Public`, performed under the `sophie.turner` user context (**Flags 9, 10, 11**).

### January 15, 2026 — Lateral Movement (as-pc1 > as-pc2)

- **04:18 UTC** — `WMIC.exe` is used in a failed remote execution attempt against `as-pc2` (**Flag 21, 22**).
- **04:24 UTC** — `PsExec.exe` is attempted against `as-pc2` and also fails (**Flag 21**).
- **04:29 UTC** — `mstsc.exe` is used to successfully pivot to `as-pc2` via RDP under the account `david.mitchell` (**Flags 23, 24, 25**).
- **04:40 UTC** — A disabled account is reactivated using `net.exe /active:yes` by `david.mitchell` (**Flags 26, 27**). AnyDesk is deployed on `as-pc2` (**Flag 20**).

### January 15, 2026 — Persistence & Lateral Movement (as-pc2 > as-srv)

- **04:43–04:44 UTC** — `BACS_Payments_Dec2025.ods` is accessed from `as-pc2` on the file server `as-srv`, with a LibreOffice lock file confirming it was opened for editing (**Flags 31, 32, 33**).
- **04:52 UTC** — Scheduled task `MicrosoftEdgeUpdateCheck` is created pointing to `C:\Users\Public\RuntimeBroker.exe`, a renamed copy of the original payload, set to run daily at 03:00 with highest privileges (**Flags 28, 29**). AnyDesk is downloaded from `sync.cloud-endpoint.net` on `as-pc2` (**Flag 8**).
- **04:54 UTC** — `mstsc.exe` is used to pivot from `as-pc2` to `as-srv` (**Flag 24**).
- **04:57 UTC** — AnyDesk is deployed on `as-srv` (**Flag 20**). Backdoor account `svc_backup` is created via `net.exe /add` (**Flag 30**).
- **04:59 UTC** — `Shares.7z` archive is created, packaging network share contents ahead of potential exfiltration (**Flags 34, 35**).
- **05:08 UTC** — `wevtutil.exe` is used to clear the `Application` and `System` event logs (**Flag 36**).
- **05:10 UTC** — Final `ClrUnbackedModuleLoaded` event recorded, confirming continued in-memory activity (**Flag 37**).

---

## 🧩 MITRE ATT&CK Mapping

| **Flag/Event** | **Tactic** (TA#) | **Technique** (T#) | **Details** |
|---|---|---|---|
| **Flag 1 — Initial Vector** | Initial Access (TA0001) | T1204.002 – User Execution: Malicious File | User executed double-extension payload masquerading as a PDF resume |
| **Flag 2 — Payload Hash** | Initial Access (TA0001) | T1204.002 – User Execution: Malicious File | SHA256 hash identifies the malicious binary |
| **Flag 3 — User Interaction** | Initial Access (TA0001) | T1204.002 – User Execution: Malicious File | `explorer.exe` as parent confirms direct user execution |
| **Flag 4 — Suspicious Child Process** | Defense Evasion (TA0005) | T1055 – Process Injection | `notepad.exe` spawned as sacrificial injection target |
| **Flag 5 — Process Arguments** | Defense Evasion (TA0005) | T1055 – Process Injection | Empty argument confirms programmatic process spawning for injection |
| **Flag 6 — C2 Domain** | Command and Control (TA0011) | T1071.001 – Web Protocols | Outbound C2 communication to `cdn.cloud-endpoint.net` |
| **Flag 7 — C2 Process** | Command and Control (TA0011) | T1071.001 – Web Protocols | Payload binary directly initiates C2 traffic |
| **Flag 8 — Staging Infrastructure** | Command and Control (TA0011) | T1105 – Ingress Tool Transfer | Secondary payloads hosted on `sync.cloud-endpoint.net` |
| **Flag 9 — Registry Targets** | Credential Access (TA0006) | T1003.002 – OS Credential Dumping: Security Account Manager | SAM and SYSTEM hives targeted for credential extraction |
| **Flag 10 — Local Staging** | Collection (TA0009) | T1074.001 – Data Staged: Local Data Staging | Credential files staged in `C:\Users\Public` |
| **Flag 11 — Execution Identity** | Credential Access (TA0006) | T1078 – Valid Accounts | Credential dumping performed under `sophie.turner` context |
| **Flag 12 — User Context** | Discovery (TA0007) | T1033 – System Owner/User Discovery | `whoami.exe` used to enumerate user identity and privileges |
| **Flag 13 — Network Enumeration** | Discovery (TA0007) | T1135 – Network Share Discovery | `net.exe view` used to enumerate accessible network shares |
| **Flag 14 — Local Admins** | Discovery (TA0007) | T1069.001 – Permission Groups Discovery: Local Groups | Administrators group queried to identify privileged accounts |
| **Flag 15 — Remote Tool** | Command and Control (TA0011) | T1219 – Remote Access Software | AnyDesk deployed as persistent remote access mechanism |
| **Flag 16 — Remote Tool Hash** | Command and Control (TA0011) | T1219 – Remote Access Software | AnyDesk binary uniquely identified by SHA256 hash |
| **Flag 17 — Download Method** | Defense Evasion (TA0005) | T1197 – BITS Jobs / T1105 – Ingress Tool Transfer | `certutil.exe` used as LOLBin to download AnyDesk |
| **Flag 18 — Configuration Access** | Command and Control (TA0011) | T1219 – Remote Access Software | AnyDesk configuration file modified for unattended access |
| **Flag 19 — Access Credentials** | Credential Access (TA0006) | T1219 – Remote Access Software | Unattended access password set for persistent remote entry |
| **Flag 20 — Deployment Footprint** | Command and Control (TA0011) | T1219 – Remote Access Software | AnyDesk deployed across all three hosts |
| **Flag 21 — Failed Execution** | Lateral Movement (TA0008) | T1021 – Remote Services | `WMIC.exe` and `PsExec.exe` attempted but failed |
| **Flag 22 — Target Host** | Lateral Movement (TA0008) | T1021 – Remote Services | `as-pc2` targeted in failed lateral movement attempts |
| **Flag 23 — Successful Pivot** | Lateral Movement (TA0008) | T1021.001 – Remote Services: RDP | `mstsc.exe` used to successfully pivot via RDP |
| **Flag 24 — Movement Path** | Lateral Movement (TA0008) | T1021.001 – Remote Services: RDP | Full path: `as-pc1 > as-pc2 > as-srv` |
| **Flag 25 — Compromised Account** | Lateral Movement (TA0008) | T1078 – Valid Accounts | `david.mitchell` credentials used for RDP lateral movement |
| **Flag 26 — Account Activation** | Persistence (TA0003) | T1098 – Account Manipulation | Disabled account reactivated via `net.exe /active:yes` |
| **Flag 27 — Activation Context** | Persistence (TA0003) | T1078 – Valid Accounts | `david.mitchell` performed account reactivation |
| **Flag 28 — Scheduled Persistence** | Persistence (TA0003) | T1053.005 – Scheduled Task/Job: Scheduled Task | `MicrosoftEdgeUpdateCheck` task created for daily execution |
| **Flag 29 — Renamed Binary** | Defense Evasion (TA0005) | T1036.005 – Masquerading: Match Legitimate Name | Payload renamed to `RuntimeBroker.exe` to blend with system processes |
| **Flag 30 — Backdoor Account** | Persistence (TA0003) | T1136.001 – Create Account: Local Account | `svc_backup` created as backdoor local account |
| **Flag 31 — Sensitive Document** | Collection (TA0009) | T1005 – Data from Local System | `BACS_Payments_Dec2025.ods` accessed on file server |
| **Flag 32 — Modification Evidence** | Collection (TA0009) | T1565.001 – Data Manipulation: Stored Data Manipulation | LibreOffice lock file confirms document opened for editing |
| **Flag 33 — Access Origin** | Lateral Movement (TA0008) | T1021.001 – Remote Services: RDP | Document accessed from `as-pc2` via remote session |
| **Flag 34 — Exfil Archive** | Collection (TA0009) | T1560.001 – Archive Collected Data: Archive via Utility | `Shares.7z` created to package data for exfiltration |
| **Flag 35 — Archive Hash** | Collection (TA0009) | T1560.001 – Archive Collected Data: Archive via Utility | SHA256 hash uniquely identifies the staged archive |
| **Flag 36 — Log Clearing** | Defense Evasion (TA0005) | T1070.001 – Indicator Removal: Clear Windows Event Logs | Application and System logs cleared via `wevtutil.exe` |
| **Flag 37 — Reflective Loading** | Defense Evasion (TA0005) | T1620 – Reflective Code Loading | `ClrUnbackedModuleLoaded` confirms in-memory .NET assembly execution |
| **Flag 38 — Memory Tool** | Credential Access (TA0006) | T1555.003 – Credentials from Password Stores: Credentials from Web Browsers | SharpChrome loaded in memory to harvest Chrome credentials |
| **Flag 39 — Host Process** | Defense Evasion (TA0005) | T1055 – Process Injection | SharpChrome injected into `notepad.exe` memory space |

---

## Conclusion

The investigation revealed a sophisticated, multi-stage intrusion spanning three corporate endpoints over the course of a single day. The attack began with a socially engineered double-extension file delivered to `sophie.turner` on `as-pc1`, which executed silently under the cover of a legitimate user interaction and immediately established C2 communication. From that initial foothold, the attacker conducted methodical reconnaissance, deployed persistent remote access infrastructure across the entire environment, harvested credentials from both registry hives and browser memory, and moved laterally through the network using compromised credentials until reaching the file server. The targeting of `BACS_Payments_Dec2025.ods` — a sensitive financial payments document — and the subsequent creation of `Shares.7z` suggest that data exfiltration was the ultimate objective. Multiple redundant persistence mechanisms, including AnyDesk, a scheduled task, a reactivated account, and a newly created backdoor account, indicate a threat actor with both the intent and the capability to maintain long-term access. Anti-forensics activity in the final phase, including log clearing and entirely in-memory tool execution via reflective loading, reflects a high degree of operational security awareness. This intrusion underscores the critical importance of monitoring for double-extension file execution, LOLBin abuse, process injection patterns, and lateral movement via legitimate remote desktop tools.

---

## 📘 Lessons Learned

This investigation highlights how a single user interaction with a convincingly named file can serve as the entry point for a deeply rooted network compromise. The attacker's use of legitimate tools throughout — `certutil.exe` for downloading, `mstsc.exe` for lateral movement, `notepad.exe` as an injection host, and AnyDesk for remote access — demonstrates the challenge of detecting intrusions that deliberately avoid custom malware in favor of living-off-the-land techniques. The reuse of the same payload hash across multiple filenames (`Daniel_Richardson_CV.pdf.exe`, `RuntimeBroker.exe`) provided a valuable pivot point that tied multiple stages of the attack together. The discovery of `ClrUnbackedModuleLoaded` through a broad `distinct ActionType` query rather than a targeted search reinforces the value of exploratory hunting techniques alongside hypothesis-driven ones. Finally, the LibreOffice lock file artifact serves as a reminder that evidence of attacker intent can surface in unexpected places — and that comprehensive file event monitoring across all endpoints, including file servers, is essential for reconstructing the full scope of a data access event.

---

**Report Completed By:** Adrian Vergara
