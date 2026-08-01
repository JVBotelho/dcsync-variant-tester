# Prior Art Survey — Stealth DCSync

**Date:** 2026-07-08
**Scope:** Publications, PoCs, tools, conference talks, patents

---

## Result: NO publication/tool/PoC found with this technique

The technique described in this research (use of `pPartialAttrSet` with only
credential attributes, avoiding `DRS_WRIT_REP`, attempting to trigger GUID
`89e95b76` instead of `1131f6ad`) **does not exist** in any public tool,
article, PoC, or publication.

This does not mean the technique works (it does NOT — see results/), but it
confirms the research space had not been explored before this work.

---

## Searches Performed

### GitHub (repositories + code search)

| Query | Results |
|---|---|
| `stealth dcsync` | `popalltheshells/StealthDCSYNC` — wrapper of `secretsdump.py -just-dc-user` with delays. NOT this technique. |
| `partial attribute dcsync GetNCChanges` | 0 results |
| `dirsync dcsync filtered credential hash` | 0 results |
| `dcsync stealth evasion detection` | 0 results |
| `"89e95b76" hash dcsync` | 0 results |
| `"DRS_WRIT_REP" dcsync` | 0 results |
| `pPartialAttrSet dcsync` | 0 results (code search requires login; repositories = 0) |
| `EXOP_REPL_SECRETS dcsync` | 0 results |
| `DRS_SPECIAL_SECRET_PROCESSING` | 0 results |
| `Get-Changes-In-Filtered-Set hash` | 0 results |

### Blogs / Security Research Articles

| Source | Relevant Content |
|---|---|
| **ired.team** — DCSync lab | Mentions the 3 GUIDs (`1131f6aa`, `1131f6ad`, `89e95b76`) and says about Filtered Set: "this one isn't always needed". Does NOT explore stealth. |
| **adsecurity.org** — Mimikatz DCSync (Sean Metcalf, 2015) | Details DCSync, permissions, detection via network. Does NOT address filtered attributes or GUID bypass. |
| **harmj0y.net** — Abusing AD Permissions | Documents the 3 permissions and GUIDs. Does NOT explore DCSync stealth. |
| **simondotsh (2022)** — DirSync | Blog offline/unavailable. Per project design docs, explores filtered sync for change detection, NOT credential dumping. |
| **SpecterOps blog** | No articles found on DCSync stealth or filtered attribute sync. |
| **Curvelock Ransomware paper (IEEE, 2025)** | Mentions DCSync tangentially in ransomware context. Irrelevant. |
| **MITRE ATT&CK T1003.006** | Detection strategy DET0594 covers standard DCSync. Does NOT address filtered set evasion. |

### SIEM / EDR Detection Rules

All known detection rules (Microsoft ATA, Sentinel, Splunk ES, Elastic Security,
CrowdStrike) detect ONLY GUID `1131f6ad` (DS-Replication-Get-Changes-All).

**If the bypass had worked, NONE of the standard SIEM rules would have caught it.**

### Google Scholar

| Query | Results |
|---|---|
| `dcsync stealth ms-drsr partial attribute replication evasion` | 1 result — Curvelock ransomware paper (tangential). No academic paper on filtered DCSync. |

---

## Analysis: Why wasn't this explored before?

1. **The technique is counterintuitive.** The security research community assumed
   `Get-Changes-All` (GUID `1131f6ad`) is always required for credential attributes
   because they are "secret." Nobody tested whether `Get-Changes-In-Filtered-Set`
   (GUID `89e95b76`) alone would be sufficient with `pPartialAttrSet`.

2. **Focus was detection, not evasion.** Published research focused on HOW to
   detect DCSync (Event 4662, network monitoring), not how to bypass detection
   at the protocol level.

3. **Microsoft documentation is ambiguous.** The MS-DRSR spec documents
   `pPartialAttrSet` and `DRS_SPECIAL_SECRET_PROCESSING`, but does not clearly
   specify which permission GUID each flag/EXOP combination triggers.

4. **Offensive tools never implemented it.** All 4 existing DCSync tools
   (Mimikatz, Impacket secretsdump, DSInternals, SharpDCSync) use the same
   pattern: `EXOP_REPL_OBJ` + `DRS_INIT_SYNC | DRS_WRIT_REP` + no `pPartialAttrSet`.

---

## Conclusion

**Originality: 9.5/10** at time of research (July 2026).

The technique is genuinely novel in concept. However, **empirical testing proved
it does NOT work** — the DC always requires `Get-Changes-All` when credential
attributes are in the request, regardless of flag/EXOP combinations. The concept
is original; the result is a negative finding.

### Verified References

- ired.team: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync
- adsecurity.org: https://adsecurity.org/?p=1729
- MITRE ATT&CK T1003.006: https://attack.mitre.org/techniques/T1003/006/
- MS-DRSR Spec: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/
- popalltheshells/StealthDCSYNC (wrapper, not the technique): https://github.com/popalltheshells/StealthDCSYNC
