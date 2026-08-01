# Methodology — Stealth DCSync Variant Testing

This document describes the lab setup, audit parity verification, and test
procedure used to evaluate whether DRS flag manipulation can avoid the
`1131f6ad` GUID (DS-Replication-Get-Changes-All) in Event 4662.

---

## Lab Setup

### Test Environment

Two domain controllers were tested:

| | Server 2016 | Server 2025 |
|---|---|---|
| OS | Windows Server 2016 Standard | Windows Server 2025 Standard Evaluation |
| Build | — | 26100 (10.0.26100) |
| Forest/Domain Level | Windows2016 | Windows2025 |
| DC Hostname | dc | dc2025 |
| DC IP | 192.168.50.227 | 192.168.50.9 |
| Domain | WINDOMAIN | WINDOMAIN2025 |

### Test Client

- Linux (Parrot OS) with Python 3 and impacket 0.13.1
- Same impacket version and harness against both DCs

### Test User

A domain user with full DCSync permissions:

```
# gitleaks:allow
net user vagrant vagrant /add /domain
```

The test user must have `Replicating Directory Changes All` (Get-Changes-All).

---

## Audit Parity Verification

**Critical: Event 4662 is NOT generated automatically.** The Security event log
only records these events when both conditions are met:

1. **Audit policy enabled** — `Audit Directory Service Access` must be `Success`
2. **SACL on domain root** — The domain naming context root must have a SACL
   entry auditing property reads

Without both conditions, comparing Event 4662 output between runs is meaningless.

### Verification Commands

#### 1. Check audit policy

```
auditpol /get /category:"DS Access"
```

Expected output:
```
Directory Service Access
  Success
```

If disabled, enable with:
```
auditpol /set /subcategory:"Directory Service Access" /success:enable
```

#### 2. Check SACL on domain root

```
dsacls "dc=windomain,dc=local"
```

Expected: output should include SACL entries. If SACL is empty, add:

```
dsacls "dc=windomain,dc=local" /S
```

**Validation baseline:** Before running any variants, execute a standard DCSync
and confirm Event 4662 appears with GUID `1131f6ad`. If no event is generated,
the audit configuration is incomplete and results will be false negatives.

```
# Run standard DCSync to baseline:
secretsdump.py -just-dc-user vagrant 'WINDOMAIN/Administrator:vagrant@192.168.50.227'  # gitleaks:allow

# Verify event on DC:
wevtutil qe Security /q:"*[System[EventID=4662]]" /c:5 /rd:true /f:text
```

---

## Test Variants

Five variants are tested against each DC version:

| # | Name | ulFlags | ulExtendedOp |
|---|---|---|---|
| V1 | Baseline | `DRS_INIT_SYNC \| DRS_WRIT_REP` (0x30) | `EXOP_REPL_OBJ` (6) |
| V2 | No WRIT_REP | `DRS_INIT_SYNC` (0x20) | `EXOP_REPL_OBJ` (6) |
| V3 | SPECIAL_SECRET | `DRS_INIT_SYNC \| DRS_SPECIAL_SECRET_PROCESSING` (0x04000020) | `EXOP_REPL_OBJ` (6) |
| V4 | REPL_SECRETS | `DRS_INIT_SYNC` (0x20) | `EXOP_REPL_SECRETS` (7) |
| V5 | Full REPL_SEC | `DRS_INIT_SYNC \| DRS_WRIT_REP` (0x30) | `EXOP_REPL_SECRETS` (7) |

All variants request only two attributes via `pPartialAttrSet`:
- `unicodePwd` (OID: 1.2.840.113556.1.4.90)
- `supplementalCredentials` (OID: 1.2.840.113556.1.4.125)

These are the minimal set of credential attributes. If the DCSync succeeds
and returns a valid password hash, the credential fetching works. The question
is which permission GUID the DC logs in Event 4662.

### What Each Variant Tests

- **V1 (Baseline):** Control group. Validates that standard flags trigger the
  expected `1131f6ad` GUID.
- **V2 (No WRIT_REP):** Tests if `DRS_WRIT_REP` is the flag that gates the
  `Get-Changes-All` permission check. If removing it switches the DC to check
  only `Get-Changes-In-Filtered-Set` (GUID `89e95b76`), the bypass works.
- **V3 (SPECIAL_SECRET):** Tests if `DRS_SPECIAL_SECRET_PROCESSING` changes
  the authorization path. This flag alters session key derivation but may
  also affect which permission is checked.
- **V4 (REPL_SECRETS):** Tests if switching from `EXOP_REPL_OBJ` to
  `EXOP_REPL_SECRETS` changes the required permission. `EXOP_REPL_SECRETS`
  is a narrower operation and might gate on a different GUID.
- **V5 (Full REPL_SEC):** Combines full flags with `EXOP_REPL_SECRETS` to
  test if any interaction between flags and extop changes behavior.

### Permission Variant

An additional test uses an account with `Get-Changes` + `Get-Changes-In-Filtered-Set`
but **without** `Get-Changes-All`:

```
net user dcsynctest "Test123!" /add /domain  # gitleaks:allow
dsacls "dc=windomain,dc=local" /I:S /G "WINDOMAIN\dcsynctest:CA;Replicating Directory Changes"
dsacls "dc=windomain,dc=local" /I:S /G "WINDOMAIN\dcsynctest:CA;Replicating Directory Changes In Filtered Set"
```

This tests whether any variant can fetch credentials with fewer permissions than
`Get-Changes-All`.

---

## Event 4662 Isolation by LogonID

When running variants in rapid sequence (automated harness), each DRS session
receives a distinct LogonID. This is critical for isolating events per variant.

### Verification

On the DC, filter Event 4662 by LogonID:

```
wevtutil qe Security /q:"*[System[EventID=4662]]" /c:30 /rd:true /f:text | findstr /i "Logon ID"
```

Each variant should have a unique LogonID. Cross-reference with the timestamp
output from the test harness to assign events to specific variants.

### Contamination Prevention

- Wait 2+ seconds between variants (configured via `--delay` in the harness)
- The harness uses a single DRS bind/session reuse for V1-V5, meaning one
  session with one LogonID per entire run
- For the `run_variants.sh` approach, each invocation creates a new SMB session
  with a new LogonID

---

## Patch Locations (impacket 0.13.1)

When using the `run_variants.sh` script, the following lines in
`impacket/examples/secretsdump.py` are modified:

```python
# Line 646 — ulFlags
request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP

# Line 649 — ulExtendedOp
request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
```

These line numbers were verified on impacket 0.13.1. Minor differences
(line 648 vs 646) have been observed across different builds of the same
version. The `run_variants.sh` script autodetects the impacket library path
and applies the correct offsets.

### Restoration

The script creates a `.pre-variant-tester.bak` backup before any patch. If
interrupted, restore manually:

```bash
cp /path/to/impacket/examples/secretsdump.py.pre-variant-tester.bak \
   /path/to/impacket/examples/secretsdump.py
```

Calling `run_variants.sh` again also restores from backup before starting a
new run (idempotent design).

---

## Interpretation of Results

### GUID Reference

| GUID | Permission | Description |
|---|---|---|
| `1131f6aa-...` | DS-Replication-Get-Changes | Baseline directory replication read |
| `1131f6ad-...` | DS-Replication-Get-Changes-All | Read all properties including secrets |
| `89e95b76-...` | DS-Replication-Get-Changes-In-Filtered-Set | Read filtered (non-secret) properties |

### Success Condition

The bypass would be considered successful if **any** variant produces Event 4662
events that contain GUID `89e95b76` **without** GUID `1131f6ad`. This would
mean the DC did not check `Get-Changes-All` — the permission that conventional
SIEM rules monitor.

### Failure Condition

If all variants produce GUID `1131f6ad` (as observed on Server 2016 and 2025),
the bypass does not work. The DC internally translates credential attribute
requests back to `Get-Changes-All` checks regardless of flags or ExtendedOp.
