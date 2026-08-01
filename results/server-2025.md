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
| Permission filtered-set-only | 0x20f7 | 0x20f7 (identical) |
| Event 4662 structure | 1x All + 2x Get-Changes | 1x All + 2x Get-Changes (identical) |
| Admin group required for DCSync | YES (Administrators) | YES (Administrators) (identical) |

**Cross-version isolation test (dcsync2):** Both 2016 and 2025 require
`BUILTIN\Administrators` (or Domain Admins) membership in addition to
`Get-Changes + Get-Changes-All` extended rights. Extended rights alone
return `0x20f7` on both versions.

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

3. **`Get-Changes-In-Filtered-Set` does NOT cover secret attributes.**
   Even on Server 2025, this permission does not grant access to `unicodePwd`
   and `supplementalCredentials`.

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

### Revised Conclusions

1. **`0x20f7` is NOT a missing-Get-Changes-All indicator.** It is returned
   when the calling user lacks administrative group membership, regardless
   of extended rights. Hypothesis (a) — "artifact of lab setup" — is
   **FALSIFIED**. The denial is real and consistent.

2. **The DCSync authorization model requires BOTH:**
   ```
   [REQUIRED] Membership in Administrators (S-1-5-32-544) or Domain Admins
   [REQUIRED] Get-Changes-All extended right on the domain NC
   ```
   Neither alone is sufficient. Extended rights without admin group = 0x20f7.
   Admin group without extended rights = not tested (but likely same).

3. **This applies to BOTH Server 2016 and Server 2025** — identical behavior
   confirmed via cross-version test. The documented tradecraft ("just delegate
   Get-Changes-All") is incomplete: it only works in practice because the
   accounts used in real attacks are typically already Administrators or
   Domain Admins.

4. **Why does this matter for detection?** SIEM rules that alert on
   `Event 4662 + GUID 1131f6ad` from non-DA users may produce false
   negatives if the adversary obtains Administrator access without
   Domain Admins. Conversely, `0x20f7` events from non-admin users
   indicate DCSync attempts — a different (and perhaps more interesting)
   detection signal than the standard 4662 alert.

5. **Harness bug (unresolved):** The custom `DRSGetNCChanges` construction
   produces `rpc_x_bad_stub_data` in all configurations. This is a
   marshaling issue, not a permission issue. Future work: monkey-patch
   secretsdump's in-memory attribute set.
