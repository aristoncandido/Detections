<div align="center">

# 🛡️ Detection Rules

### Threat-informed detection engineering — one threat at a time, mapped to MITRE ATT&CK

<p>
  <img src="https://img.shields.io/badge/Format-Sigma-EF4444?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Targets-Splunk%20%7C%20Elastic%20%7C%20Wazuh-0EA5E9?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Mapped_to-MITRE_ATT%26CK-CC0000?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Validated_with-Atomic_Red_Team-22C55E?style=for-the-badge" />
</p>

</div>

---

## What this is

This repo is my working detection engineering practice. Every rule here starts from a **real threat** — a DFIR report, a CISA advisory, an observed TTP — and ends as a **validated, portable detection** that I can drop into Splunk, Elastic, or Wazuh.

The philosophy is simple:

> **For every offensive technique, write a detection. For every detection, validate that it fires.**

A rule that was never tested isn't a detection — it's a hope. Everything here is emulated with Atomic Red Team before it ships.

---

## How each detection is built

Every rule follows the same five-phase lifecycle:

```
1. INTELLIGENCE   →  Mine a real threat (DFIR Report, MITRE, CISA, vendor intel)
2. RESEARCH       →  Extract the TTP, apply the Pyramid of Pain (detect behavior, not hashes)
3. DEVELOPMENT    →  Author once in Sigma → convert to SPL / KQL / Wazuh XML
4. VALIDATION     →  Emulate with Atomic Red Team, confirm the rule fires
5. OPERATION      →  Deploy, hunt retroactively, tune false positives
```

The **Pyramid of Pain** drives every rule: I detect at the behavior/TTP level, not at the hash or IP level. Hashes change in seconds; behaviors are expensive for an attacker to abandon.


## Case study 001 — The Gentlemen Ransomware

A real intrusion chain documented by [The DFIR Report](https://thedfirreport.com/), starting with a **fake Sysinternals MSI** and ending in domain-wide ransomware. I broke the kill chain into stages and wrote a detection for each — because the earlier you catch the chain, the more of the attack you prevent.

| # | Stage | Detection | MITRE ATT&CK | Severity |
|---|---|---|---|---|
| 1 | Initial Access | `node.exe` spawned by `msiexec.exe` | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) · [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | High |
| 3 | Persistence | Registry Run key written via command line | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | High |
| 4 | Credential Access | LSASS dump via `rundll32` + `comsvcs.dll` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Critical |
| 5 | Lateral Movement | Unauthorized RMM service install (GoTo Resolve, AnyDesk…) | [T1219](https://attack.mitre.org/techniques/T1219/) | High |

> **Why no rule for the ransomware itself (stage 7)?** Because by the time the ransomware fires, it's already too late. Detection lives in the *earlier* stages — the LSASS dump, the suspicious Run key, the RMM appearing where it shouldn't. This is "shift left" for detection.

---

## Example — write once, run anywhere

Every detection is authored in **Sigma** as the single source of truth, then converted to each platform.

**Sigma:**
```yaml
title: LSASS Memory Dump via comsvcs.dll MiniDump
id: 8f2d1a40-de02-0002
status: experimental
description: Detects credential dumping from LSASS abusing rundll32 + comsvcs.dll
references:
    - https://attack.mitre.org/techniques/T1003/001/
author: Ariston Cândido
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\rundll32.exe'
    selection_cmd:
        CommandLine|contains: 'comsvcs'
        CommandLine|contains:
            - 'MiniDump'
            - '#24'
    condition: selection_img and selection_cmd
level: critical
tags:
    - attack.t1003.001
    - attack.credential_access
```

**Splunk (SPL):**
```spl
index=* (Image="*\\rundll32.exe" CommandLine="*comsvcs*"
(CommandLine="*MiniDump*" OR CommandLine="*#24*"))
| table _time, host, user, Image, CommandLine
```

**Wazuh (`local_rules.xml`):**
```xml
<rule id="100071" level="14">
  <if_sid>91802</if_sid>
  <field name="win.eventdata.image">rundll32\.exe$</field>
  <field name="win.eventdata.commandLine">comsvcs</field>
  <description>Credential Dumping: LSASS dump via comsvcs.dll - T1003.001</description>
  <mitre><id>T1003.001</id></mitre>
</rule>
```

---

## Validation

Detections are emulated before they're trusted. Example for the LSASS rule:

```powershell
# Atomic Red Team — emulate T1003.001 (comsvcs.dll dump)
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
Invoke-AtomicTest T1003.001 -TestNumbers 4
Invoke-AtomicTest T1003.001 -TestNumbers 4 -Cleanup
```

Then confirm the rule fired:
```spl
index=* Image="*\\rundll32.exe" CommandLine="*comsvcs*" earliest=-15m
```

✅ Fires → ship it · ❌ Silent → fix the rule, never the other way around.

---

## Frameworks & references

- 🎯 [MITRE ATT&CK](https://attack.mitre.org/) — every rule is tagged to a technique
- 🛡️ [Sigma HQ](https://github.com/SigmaHQ/sigma) — detection format & conversion
- ⚛️ [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — validation
- 📚 [The DFIR Report](https://thedfirreport.com/) — primary threat intelligence source
- 🧭 Detection logic documented in [Palantir ADS](https://github.com/palantir/alerting-detection-strategy-framework) format

---

## Roadmap

- [ ] One new detection per week, sourced from a fresh threat report
- [ ] Automated Sigma → SPL/KQL/Wazuh conversion in CI (Detection-as-Code)
- [ ] ATT&CK Navigator coverage layer published in the repo
- [ ] Coverage gap analysis with DeTT&CT

---

<div align="center">

**Built by Ariston Cândido** · Cybersecurity Engineer · Detection Engineering

<a href="https://www.linkedin.com/in/ariston-candido"><img src="https://img.shields.io/badge/LinkedIn-0A66C2?style=flat&logo=linkedin&logoColor=white" /></a>

<i>Defense in depth. Offense for context. Detection as the loop that connects them.</i>

</div>
