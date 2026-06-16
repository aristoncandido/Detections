# 1 · Intelligence

**Source:** The DFIR Report — Flash Alert
**Title:** EtherRAT and TukTuk C2 End in The Gentlemen Ransomware
**Date:** 2026/05/11
**Link:** https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/

## Summary

A malicious MSI disguised as the Sysinternals suite installs **EtherRAT**, which retrieves dynamic C2 configuration from the Ethereum blockchain (**EtherHiding**), then pulls the **TukTuk** framework via DLL sideloading. The actor uses the **GoTo Resolve** RMM for lateral movement, dumps credentials (Kerberoasting, LSASS/NTDS), exfiltrates data with **Rclone** to **Wasabi**, and finishes with **The Gentlemen** ransomware deployed via a malicious GPO.

## Why this report

- Recent, real-world intrusion with a full kill chain
- Includes a DEATH section (Detection Engineering and Threat Hunting) with real commands
- Mixes a classic chain with uncommon tooling (EtherHiding, EtherRAT, TukTuk) — good for building durable, behavior-based detections

## EtherHiding note

The Ethereum blockchain is **not** the C2 server. It is an immutable, takedown-resistant intermediary that stores the (obfuscated) C2 configuration. The implant reads the blockchain to learn the *currently active* C2 domain. Blocking the C2 server alone is ineffective — the attacker simply rewrites the on-chain config. Detection therefore focuses on host behavior, not C2 indicators.

## TTPs selected for this week

| Stage | Technique | MITRE |
|---|---|---|
| Initial Access | Fake MSI spawning Node.js | T1218.007 / T1059.007 |
| Persistence | Registry Run key | T1547.001 |
| Credential Access | LSASS dump via comsvcs.dll | T1003.001 |
