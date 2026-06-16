# 2 · Research

## Kill chain

```
1. Initial Access     Fake Sysinternals MSI (SEO poisoning / malvertising)
2. Execution          EtherRAT via portable Node.js + obfuscated JS
3. Persistence + C2   Registry Run key  +  EtherHiding (reads Ethereum blockchain) -> TukTuk
4. Credential Access  Kerberoasting + LSASS/NTDS dump
5. Lateral Movement   GoTo Resolve (RMM) + RDP / SMB / WinRM
6. Exfiltration       Rclone -> Wasabi cloud (double extortion)
7. Impact             The Gentlemen ransomware deployed via malicious GPO
```

## Pyramid of Pain — where we detect

Detect at the **TTP / behavior** level, not at hashes or IPs. Hashes and C2 domains rotate (EtherHiding makes C2 takedown useless); behaviors are expensive for the attacker to abandon.

| Detect (durable) | Avoid relying on (fragile) |
|---|---|
| `msiexec.exe` -> `node.exe` (anomalous parent/child) | MSI file name / hash |
| `rundll32 + comsvcs.dll + MiniDump` | output dump file name (`im4.txt`) |
| `reg add ...\CurrentVersion\Run` | specific Run key value |
| RMM service install outside allowlist | specific RMM binary hash |
| — | C2 domains (rotate via blockchain) |

## Evidence -> detection mapping

### Stage 1 — Initial Access (T1218.007 / T1059.007)
Legitimate Sysinternals installers never spawn Node.js. The anomaly is the parent/child relationship: `msiexec.exe -> node.exe`. Everything runs under signed, trusted binaries (living-off-the-land), so file-based detection fails — the behavior is the signal.

### Stage 3 — Persistence (T1547.001)
EtherRAT writes a Run key via `reg.exe` to survive reboots. Needs baselining (legit installers do this too), so this is a candidate for an allowlist before alerting.

### Stage 4 — Credential Access (T1003.001)
Real command observed (case-obfuscated in the report):
`rundll32.exe comsvcs.dll, #24 ... lsass ... full`
Detect the pair `rundll32 + comsvcs.dll + MiniDump/#24`. Case-insensitive matching required. Near-zero false positives — `critical`.

## Detection priority

Catching **Stage 4 (LSASS dump)** is the highest-value rule: without stolen credentials the attacker is stuck on a single host and cannot move laterally. Earlier detection = more of the attack prevented ("shift left").
