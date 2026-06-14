# 06 — NFS & RPC

> **Module:** Network Enumeration
> **Difficulty:** Beginner
> **RTO Relevance:** Medium — NFS misconfigurations lead to sensitive file access

---

## What is RPC?

RPC (Remote Procedure Call) is a protocol that allows a program on one computer to **execute code or functions on another computer** over a network — as if they were running locally.

Think of it like calling a function in your code, but that function actually runs on a remote server:

```
Your Computer                    Remote Server
    │                                 │
    │── "Run function: GetUserList" → │
    │                                 │
    │ ←── Returns user list ───────── │
    │   (as if it ran locally)        │
```

Windows uses RPC extensively for services, AD communication, and remote management.

---

## What is NFS?

NFS (Network File System) is a **Linux/Unix file sharing protocol** — the Linux equivalent of Windows SMB. It allows computers to mount and access remote file systems as if they were local drives.

```
Linux Client                     NFS Server
    │                                 │
    │── "Mount /home/shared" ───────→ │
    │                                 │
    │ ←── File system accessible ──── │
    │   (appears as local folder)     │
```

---

## Important Ports

| Port | Protocol | Service |
|------|----------|---------|
| TCP/UDP 111 | Portmapper/rpcbind | RPC service registry |
| TCP/UDP 2049 | NFS | Network File System |
| TCP 135 | Windows RPC | Windows RPC endpoint mapper |

---

## Red Team Perspective — RPC

### Enumerating Windows RPC

```bash
# rpcclient — interact with Windows RPC
rpcclient -U "" -N 192.168.1.10

# -U "" = blank username
# -N = no password
# If null session allowed, you get an rpcclient prompt

# Inside rpcclient:
rpcclient $> enumdomusers      # List all domain users
rpcclient $> enumdomgroups     # List all groups
rpcclient $> querydominfo      # Domain info + password policy
rpcclient $> netshareenum      # List network shares
```

### What RPC Leaks (Without Any Credentials)

```
rpcclient null session → enumdomusers
    ↓
Full list of domain users:
user:[Administrator] rid:[0x1f4]
user:[ali.hassan] rid:[0x44f]
user:[svc.database] rid:[0x450]   ← Service account!
user:[sara.khan] rid:[0x451]
    ↓
Username list = foundation for password spraying
```

---

## Red Team Perspective — NFS

### Step 1 — Discover NFS Shares

```bash
# List all NFS exports on a target
showmount -e 192.168.1.20

# Output:
# Export list for 192.168.1.20:
# /home/backup    *          ← Anyone can mount this!
# /var/www/html   10.0.0.0/24
```

### Step 2 — Mount the Share

```bash
# Create a local mount point
mkdir /tmp/nfs-mount

# Mount the remote NFS share locally
mount -t nfs 192.168.1.20:/home/backup /tmp/nfs-mount

# Browse the mounted share
ls -la /tmp/nfs-mount/
```

### Step 3 — What You Might Find

```
/tmp/nfs-mount/
├── id_rsa              ← SSH private key! (instant shell access)
├── .bash_history       ← Command history (may contain passwords)
├── passwords.txt       ← (Yes, people really do this)
├── backup.sql          ← Database backup with credentials
└── config.php          ← Application config with DB passwords
```

### NFS no_root_squash Vulnerability

By default, NFS maps the `root` user from a client to an anonymous user (root squashing = security feature). But if misconfigured with `no_root_squash`:

```bash
# On NFS server config (/etc/exports):
/home/backup *(rw,no_root_squash)   ← Dangerous!

# This means: root on ANY client = root on the NFS share
# Attacker can:
# 1. Create SUID binary on mounted share as root
# 2. Execute it on the target server
# 3. Get root shell on the server
```

---

## Defense Perspective

| Defense | How It Helps |
|---------|-------------|
| Disable null sessions | Prevents unauthenticated RPC enumeration |
| NFS authentication | Require Kerberos auth for NFS |
| Remove no_root_squash | Prevents privilege escalation via NFS |
| Restrict NFS exports | Only specific IPs can mount shares |
| Firewall port 2049 | Block external NFS access |

---

## Key Takeaways

- RPC = Remote function execution protocol
- NFS = Linux file sharing (Linux's version of SMB)
- Key ports: **111** (rpcbind), **2049** (NFS), **135** (Windows RPC)
- Tool: `rpcclient` — enumerate Windows users/groups via RPC
- Tool: `showmount` — discover NFS shares
- NFS misconfigurations = direct access to sensitive files
- `no_root_squash` = critical NFS misconfiguration → privilege escalation

---
