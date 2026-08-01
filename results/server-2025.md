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
