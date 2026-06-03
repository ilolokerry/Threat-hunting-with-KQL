# KC7 CloutHaus — Threat Hunt Report
### *Following the Digital Footprints of a Spear-Phishing Campaign*

---

## The Story So Far

> *"She built her brand in public. The attacker used that against her."*

Afomiya Storm is a 25-year-old influencer partner at **CloutHaus**, a talent management platform. With a growing audience, frequent brand deals, and an open communication style, she's exactly the kind of target a threat actor looks for — high visibility, frequent external contact, and no MFA.

This report documents my full KQL investigation into how a crafted phishing email led to full mailbox compromise and sensitive data exfiltration.

---

## Data Sources Used

| Table | Purpose |
|---|---|
| `Employees` | Victim identity & risk posture |
| `Email` | Phishing artifact & exfiltration detection |
| `OutboundNetworkEvents` | Link click confirmation |
| `InboundNetworkEvents` | Attacker reconnaissance |
| `PassiveDns` | Infrastructure pivoting |
| `AuthenticationEvents` | Malicious login tracking |

---

## Phase 1 — Who Is the Target?

```kusto
Employees
| where name contains "Afomiya"
| project name, role, email_addr, username, hostname, mfa_enabled, ip_addr
```

**What I found:**

| Field | Value |
|---|---|
| Name | Afomiya Storm |
| Role | Influencer Partner |
| Email | afomiya_storm@clouthaus.com |
| Username | afstorm |
| Hostname | OQPA-DESKTOP |
| MFA Enabled | False |
| Internal IP | 10.10.0.3 |

> **MFA was disabled.** For a role with heavy external communication, this is a critical gap. One stolen password = full account access.

---

## Phase 2 — The Phishing Email

```kusto
Email
| where recipient == "afomiya_storm@clouthaus.com"
| where subject contains "Dior"
| project timestamp, sender, reply_to, subject, verdict, links
```

**Artifact recovered:**
Timestamp : 2025-04-03T10:41:00Z
Sender    : collabs@dior-partners.com
Subject   : [EXTERNAL] Exclusive Partnership Opportunity with Dior
Verdict   : CLEAN  <- bypassed email filtering
Link      : https://super-brand-offer.com/login

> The email impersonated Dior — a luxury brand Afomiya would realistically want to partner with. The email security system marked it **CLEAN**, meaning it slipped past filters undetected.

---

## Phase 3 — The Click

```kusto
OutboundNetworkEvents
| where src_ip == "10.10.0.3"
| where url contains "super-brand-offer.com"
| project timestamp, method, url, user_agent
```

**Two events, two seconds apart:**

| Timestamp | URL |
|---|---|
| 2025-04-03T11:20:00Z | `https://super-brand-offer.com/login` |
| 2025-04-03T11:20:02Z | `https://super-brand-offer.com/login?username=afstorm&password=**********` |

> She clicked the link and submitted her credentials to the fake login page. The attacker harvested her username and password within **2 seconds** of her landing on the page.

---

## Phase 4 — Infrastructure Pivoting

### Step 1 — Resolve the phishing domain

```kusto
PassiveDns
| where domain == "super-brand-offer.com"
| project timestamp, domain, ip
```
IP: 198.51.100.12

### Step 2 — Find all domains on that IP

```kusto
PassiveDns
| where ip == "198.51.100.12"
| distinct domain
```

**3 domains, 1 attacker:**
super-brand-offer.com
dior-partners.com
influencer-deals.net

> All three domains are hosted on the same IP — classic infrastructure reuse. The attacker built an entire fake ecosystem targeting influencers.

---

## Phase 5 — Malicious Logins

```kusto
AuthenticationEvents
| where username == "afstorm"
| where src_ip != "10.10.0.3"
| project timestamp, hostname, src_ip, user_agent, result
```

**Login from email server:**
Timestamp  : 2025-04-03T12:20:00Z
Hostname   : MAIL-SERVER01
Source IP  : 182.45.67.89
User-Agent : Mozilla/5.0 (compatible; MSIE 5.0; Windows NT 5.2; Trident/4.1)
Result     : Successful Login

**Login to workstation (4 days later):**
Timestamp  : 2025-04-07T14:11:23Z
Hostname   : OQPA-DESKTOP
Source IP  : 109.52.231.254
Result     : Successful Login
Hash       : a2feaddef8e617fa9cf861b3b49b1dd5

> The User-Agent `MSIE 5.0 / Windows NT 5.2` is from ~2003. No real user browses with this — it is attacker tooling. The login IP also resolves via PassiveDNS to `influencer-deals.net`, directly tying it to the phishing infrastructure.

---

## Phase 6 — Attacker Reconnaissance

```kusto
InboundNetworkEvents
| where src_ip == "182.45.67.89"
| where method in ("GET", "POST")
| project timestamp, url
```

**Suspicious search found:**
https://clouthaus.com/search=How+to+hack+an+influencer's+location+from+their+Instagram+story

> The attacker was not just after credentials — they were researching how to **physically locate** Afomiya using her Instagram content. This crosses from cybercrime into real-world stalking territory.

---

## Phase 7 — Exfiltration via Email Forwarding

```kusto
let victim = "afomiya_storm@clouthaus.com";
Email
| where reply_to == victim
| where recipient !endswith "@clouthaus.com"
| project timestamp, subject, recipient, links, attachments
| order by timestamp asc
```

**Exfiltration event:**
Timestamp : 2025-04-08T15:55:21Z
Subject   : [EXTERNAL] [FORWARD] Afomiya's payment details - direct deposit form
Recipient : noreply@influencer-deals.net

> No attachment needed — data shared via embedded cloud link, bypassing attachment-based DLP entirely.

Additional keyword hunts confirmed theft of:
- Identity documents (passport scan)
- Financial records (bank statements, tax documents)

---

## Attack Timeline
2025-03-31  Attacker registers infrastructure (198.51.100.12)
└── super-brand-offer.com / dior-partners.com / influencer-deals.net
2025-04-03 10:41  Phishing email sent to afomiya_storm@clouthaus.com
2025-04-03 11:20  Afomiya clicks link & submits credentials
2025-04-03 12:20  Attacker logs into MAIL-SERVER01 from 182.45.67.89
└── Recon search for victim physical location
2025-04-07 14:11  Attacker logs into OQPA-DESKTOP (workstation access)
2025-04-08 15:55  Sensitive documents exfiltrated via email forwarding
└── Recipient: noreply@influencer-deals.net

---

## Key Analyst Takeaways

- **`reply_to` is the exfiltration pivot** — forwarded emails preserve the victim's address even when sent externally
- **Attachmentless exfil is real** — cloud links bypass attachment-based DLP
- **Infrastructure reuse exposes attackers** — one PassiveDNS pivot revealed the entire domain cluster
- **Legacy User-Agents are a beacon** — no real user browses with IE5 in 2025
- **Recon precedes visible compromise** — location recon happened before any exfiltration

---

## Defensive Recommendations

| Priority | Recommendation |
|---|---|
| Critical | Enforce MFA for all accounts, especially high-visibility roles |
| Critical | Alert on logins from IPs tied to known phishing infrastructure |
| High | Flag anomalous User-Agents on authentication events |
| High | Monitor `reply_to` mismatches in outbound email |
| Medium | Keyword-scan forwarded email subjects for sensitive document types |
| Medium | Build PassiveDNS domain clustering into threat intel workflows |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Gather Victim Identity Information | T1589 |
| Reconnaissance | Search Open Websites / Domains | T1593 |
| Initial Access | Spearphishing Link | T1566.002 |
| Credential Access | Credential Harvesting via Phishing | T1539 |
| Collection | Email Collection — Remote | T1114.002 |
| Collection | Email Forwarding Rule | T1114.003 |
| Exfiltration | Exfiltration Over Web Service | T1567 |

---

*Investigation completed using Azure Data Explorer (ADX) and KQL as part of the KC7 CloutHaus scenario.*
