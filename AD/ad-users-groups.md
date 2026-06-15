# 03 — AD Users, Groups & ACLs

> **Module:** Active Directory
> **Difficulty:** Intermediate
> **RTO Relevance:** Critical — Understanding privilege levels and ACLs is how you plan your escalation path

---

## Why This Matters to an RTO

When you first land inside a network, the first question is always:

> **"Who am I, and how do I become Domain Admin?"**

Understanding user types, group memberships, and ACL permissions is how you answer that question and map the path from your current low-privilege access to complete domain control.

---

## User Account Types

### 1. Regular Domain User
```
Example: ali.hassan@techcorp.local
├── Can log into domain computers
├── Can access resources they have permission for
├── Cannot modify AD objects
└── RTO: This is your typical starting point after initial access
```

### 2. Service Account
```
Example: svc.database@techcorp.local
├── Created for software/services (SQL Server, IIS, backup software)
├── Often has elevated privileges on specific machines
├── Password typically NEVER expires (set years ago, often weak)
├── Has an SPN registered (makes it Kerberoastable)
└── RTO: PRIMARY Kerberoasting target — high privilege, weak password
```

### 3. Administrator Account
```
Example: domain.admin@techcorp.local
├── Full control over the entire domain
├── Can add/remove users and computers
├── Can modify GPOs
├── Can access any machine in the domain
└── RTO: The ultimate credential to obtain
```

### Privilege Ladder

```
Enterprise Admin          ← Entire Forest control
        ↑
Domain Admin              ← Entire Domain control (main target)
        ↑
Server Operators          ← Can manage domain servers
        ↑
Account Operators         ← Can create/modify user accounts
        ↑
Local Administrator       ← Admin on specific machines only
        ↑
Regular Domain User       ← Starting point for RTO
```

---

## Groups — Two Types

### Security Groups
Used to **assign permissions** to multiple users at once:

```
Domain Admins
└── Members: domain.admin, umar.admin, it.superadmin
    └── Effect: All members have full domain control

Sales Team
└── Members: ali.hassan, sara.khan, ahmed.raza
    └── Effect: All members can access \\fileserver\sales

Backup Operators
└── Members: backup.svc
    └── Effect: Can backup/restore DC (read NTDS.dit!)
```

### Distribution Groups
Used only for **email distribution lists** — no security relevance:

```
All Employees
└── Members: every user in company
    └── Effect: Mass email delivery only
    └── RTO: No value from a security perspective
```

---

## Critical Built-in Groups — RTO Target List

| Group | Privileges | RTO Value |
|-------|-----------|-----------|
| **Domain Admins** | Full domain control | 🔴 Primary target |
| **Enterprise Admins** | Full forest control | 🔴 Ultimate target |
| **Schema Admins** | Modify AD blueprint | 🔴 Extremely sensitive |
| **Backup Operators** | Can backup DC → read NTDS.dit | 🟠 Underestimated |
| **Account Operators** | Create/modify users | 🟠 Useful for persistence |
| **Server Operators** | Manage domain servers | 🟡 Lateral movement |
| **Remote Desktop Users** | RDP to machines | 🟡 Lateral movement |
| **DNS Admins** | Manage DNS | 🟠 DLL injection → SYSTEM |

### The Backup Operators Trap

Many defenders overlook Backup Operators. But consider what backup requires:

```
Backup Operators can backup the Domain Controller
        ↓
DC backup = copy of NTDS.dit + SYSTEM hive
        ↓
NTDS.dit + SYSTEM = all password hashes in the domain
        ↓
Backup Operators → effectively Domain Admin in disguise
```

### DNS Admins Privilege Escalation

```
If you compromise a DNS Admin account:
        ↓
DNS server loads DLL files for plugins
        ↓
Inject malicious DLL via DNS admin privileges
        ↓
DNS service runs as SYSTEM
        ↓
Your DLL executes as SYSTEM
        ↓
Full control of the DNS server (often the DC itself)
```

---

## ACLs — Access Control Lists

### What is an ACL?

Every object in Active Directory (users, groups, computers, OUs) has an **ACL** — a list defining exactly who can do what to that object.

```
ali.hassan (User Object)
│
└── ACL (Access Control List):
    ├── Domain Admins → Full Control
    ├── ali.hassan → Read (can view own profile)
    ├── HR Team → Write (can update HR fields)
    └── IT Support → Reset Password
```

### ACL Components

| Component | Meaning |
|-----------|---------|
| ACL | The entire list of access rules |
| ACE | One individual rule in the list |
| DACL | List of who has access (Discretionary ACL) |
| SACL | Audit log of access attempts (System ACL) |

---

## ACL Abuse — RTO's Favorite Technique

ACL misconfigurations are **extremely common** in real enterprise environments and are one of the most powerful privilege escalation paths.

### Dangerous ACE Permissions

| Permission | What It Allows | RTO Abuse |
|------------|---------------|-----------|
| **GenericAll** | Full control of object | Change password, add to groups |
| **GenericWrite** | Modify any attribute | Set SPN → Kerberoast |
| **WriteOwner** | Become object owner | Gain full control |
| **WriteDACL** | Modify ACL itself | Grant yourself any permission |
| **ForceChangePassword** | Reset password without knowing current | Account takeover |
| **AllExtendedRights** | All extended permissions | Password replication, etc. |
| **AddMember** | Add members to group | Add self to Domain Admins |

### Real ACL Abuse Scenarios

**Scenario 1 — GenericWrite → Kerberoasting**
```
BloodHound reveals:
ali.hassan has GenericWrite on svc.database
        ↓
GenericWrite = can modify svc.database's attributes
        ↓
Set a fake SPN on svc.database:
Set-DomainObject -Identity svc.database -Set @{serviceprincipalname='fake/spn'}
        ↓
Now svc.database is Kerberoastable
        ↓
Request ticket, crack offline
        ↓
svc.database password obtained
```

**Scenario 2 — ForceChangePassword**
```
BloodHound reveals:
IT Support group has ForceChangePassword on sara.khan
        ↓
Compromised an IT Support account
        ↓
Reset sara.khan's password without knowing current password
        ↓
Login as sara.khan
```

**Scenario 3 — WriteDACL → Full Control**
```
ali.hassan has WriteDACL on Domain Admins group
        ↓
Modify Domain Admins ACL to give ali.hassan GenericAll
        ↓
Now ali.hassan has full control of Domain Admins group
        ↓
Add ali.hassan to Domain Admins
        ↓
Domain Admin achieved
```

**Scenario 4 — AddMember**
```
ali.hassan has AddMember rights on IT Admins group
        ↓
Add ali.hassan to IT Admins
        ↓
IT Admins have local admin on all servers
        ↓
Now ali.hassan is local admin on all servers
```

---

## BloodHound — Visualizing ACL Abuse Paths

BloodHound is a tool that maps the entire AD environment as a **graph** and automatically finds attack paths:

```bash
# Step 1: Collect data with SharpHound (on target)
.\SharpHound.exe -c All

# Step 2: Import into BloodHound
# File → Import Data → select SharpHound zip

# Step 3: Run queries
# "Find Shortest Path to Domain Admins"
# "Find Principals with DCSync Rights"
# "Find AS-REP Roastable Users"
```

**BloodHound Output Example:**
```
ali.hassan
    │
    └── Member of → IT Support Group
            │
            └── GenericWrite on → svc.database
                    │
                    └── Member of → Server Operators
                            │
                            └── Can PSRemote to → DC01
                                    │
                                    └── Domain Controller ← TARGET
```

BloodHound turns a complex AD environment into a **clear attack roadmap**.

---

## PowerView — Enumerating from Inside

PowerView is a PowerShell script for AD enumeration that uses built-in Windows APIs — making it stealthy:

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Get all domain users
Get-NetUser | select samaccountname, description, pwdlastset

# Get all groups
Get-NetGroup

# Find where you have local admin access
Find-LocalAdminAccess

# Get ACL permissions on a specific object
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Find Kerberoastable accounts
Get-NetUser -SPN | select samaccountname, serviceprincipalname

# Find AS-REP Roastable accounts
Get-NetUser -PreauthNotRequired

# Find computers where Domain Admins are logged in
Find-DomainUserLocation -GroupName "Domain Admins"
```

---

## Key Takeaways

- Three user types: Regular User (starting point), Service Account (Kerberoasting target), Admin (end goal)
- Groups define permissions — being in the right group = privilege escalation
- Backup Operators and DNS Admins are **dangerously underestimated** groups
- ACL = Every AD object has a permission list
- ACL misconfigurations are extremely common in real environments
- Key dangerous permissions: **GenericAll, GenericWrite, WriteDACL, ForceChangePassword**
- **BloodHound** — visualizes attack paths automatically
- **PowerView** — silent AD enumeration using built-in Windows APIs

---
