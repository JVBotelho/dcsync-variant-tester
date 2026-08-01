# DCSync Variant Tester

Test whether DRS flag manipulation prevents GUID `1131f6ad` (DS-Replication-Get-Changes-All)
from appearing in Event 4662 on a domain controller during credential dumping.

**Result: It does NOT work.** The DC always checks `Get-Changes-All` when credential
attributes are requested, regardless of flag combinations. Confirmed on Windows Server
2016 and Windows Server 2025 (build 26100). [Full results →](results/)

> Blog post: (link to be added when the post is published)

---

## Quickstart

```bash
pip install "impacket>=0.12.0,<0.14.0"

python3 tester/stealth_dcsync_test.py \
    --dc <dc-ip> \
    --domain <DOMAIN> \
    -u <admin-user> \
    -p <password>
```

The harness runs 5 DRSGetNCChanges variants (V1-V5) and prints timestamps plus
a `wevtutil` command to run on the DC. See [tester/README.md](tester/README.md) for
details and alternative usage via patched secretsdump.py.

---

## What This Tests

When a DCSync tool requests password hashes, the DC logs Event 4662 with GUID
`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All). Most
SIEM/EDR detections monitor this GUID exclusively.

This repository tests whether manipulating the DRS request flags — removing
`DRS_WRIT_REP`, using `DRS_SPECIAL_SECRET_PROCESSING`, or switching to
`EXOP_REPL_SECRETS` — can cause the DC to check only
`Get-Changes-In-Filtered-Set` (GUID `89e95b76`) instead, making the operation
invisible to standard detections.

**Answer: No.** On every variant and every DC version tested, the DC logs
`1131f6ad` because the permission check is based on the **attributes requested**
(`unicodePwd`, `supplementalCredentials`), not the DRS flags.

---

## Results Summary

| Variant | Flags | Server 2016 | Server 2025 |
|---|---|---|---|
| V1 Baseline | `INIT_SYNC \| WRIT_REP` | `1131f6ad` | `1131f6ad` |
| V2 No WRIT_REP | `INIT_SYNC` | `1131f6ad` | `1131f6ad` |
| V3 SPECIAL_SECRET | `INIT_SYNC \| SPECIAL_SECRET` | `1131f6ad` | `1131f6ad` |
| V4 REPL_SECRETS | `INIT_SYNC`, `EXOP_REPL_SECRETS` | `1131f6ad` | `1131f6ad` |
| V5 REPL_SEC full | `INIT_SYNC \| WRIT_REP`, `EXOP_REPL_SECRETS` | `1131f6ad` | `1131f6ad` |

[Server 2016 full results →](results/server-2016.md)
[Server 2025 full results →](results/server-2025.md)

---

## Contributing Results from Other Versions

This research only tested Windows Server 2016 and 2025. If you have access to
a DC running **Windows Server 2008 R2**, **2012**, or **2012 R2**, your results
would be valuable.

### How to contribute:

1. Clone this repo and run the harness against your DC
2. Collect `wevtutil` output for Event 4662 across all 5 variants
3. Open an issue or PR with:
   - DC OS version and build number
   - Forest/Domain functional level
   - The raw Event 4662 GUIDs for each variant
   - Confirmation that audit parity was verified (auditpol + dsacls)

Use the format in [results/server-2025.md](results/server-2025.md) as a template.

---

## Limitations

- **Audit Dependent:** Event 4662 only appears when both `Audit Directory Service
  Access` is enabled AND the domain root has a SACL for property reads. Without
  this configuration, the comparison is invalid. See [docs/methodology.md](docs/methodology.md).
- **Versions Tested:** Windows Server 2016 and 2025 only. Behavior on 2008 R2, 2012
  and 2012 R2 is unknown.
- **Impacket Pin:** Tested with impacket 0.13.1. Newer versions may change the
  DRSGetNCChanges structure layout; patch line numbers in `run_variants.sh` apply
  to 0.13.1.
- **Domain Admin Required:** The test account must hold `Replicating Directory
  Changes All` — this is an authorized operation, not an exploit. The research
  explores whether the *detection* can be bypassed, not whether the *operation*
  can be performed without permission.

---

## Repository Structure

```
dcsync-variant-tester/
├── README.md
├── LICENSE                  (MIT)
├── .gitignore
├── .gitleaks.toml
├── tester/
│   ├── README.md            (quickstart)
│   ├── stealth_dcsync_test.py   (standalone harness)
│   └── run_variants.sh      (shell wrapper — patches secretsdump.py)
├── results/
│   ├── server-2016.md
│   └── server-2025.md
└── docs/
    ├── methodology.md
    └── prior-art.md
```

---

## License

MIT — see [LICENSE](LICENSE).
