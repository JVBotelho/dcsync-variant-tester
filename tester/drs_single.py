#!/usr/bin/env python3
"""Single-shot DRS request for permission control testing.

Usage:
  python3 drs_single.py --dc 192.168.50.9 --domain WINDOMAIN2025 \\
      -u dcsynctest -p Test123! \\
      --attrs 1.2.840.113556.1.4.1 1.2.840.113556.1.4.28

Returns timestamp, success/failure, and byte counts for each requested attribute.
"""
import argparse
import datetime
import sys
from impacket.dcerpc.v5 import drsuapi, transport, epm, dtypes
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.smbconnection import SMBConnection

DEFAULT_ATTRS = [
    "1.2.840.113556.1.4.90",   # unicodePwd
    "1.2.840.113556.1.4.125",  # supplementalCredentials
]

NON_SECRET_ATTRS = [
    "1.2.840.113556.1.4.1",    # name
    "1.2.840.113556.1.4.28",   # objectClass
    "1.2.840.113556.1.4.167",  # instanceType
]


def build_parser():
    p = argparse.ArgumentParser(description="Single-shot DRS request")
    p.add_argument("--dc", required=True)
    p.add_argument("--domain", required=True)
    p.add_argument("-u", "--user", required=True)
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--attrs", nargs="+", default=None,
                   help="OIDs to request. Use 'secret' or 'non-secret' presets, or list OIDs.")
    p.add_argument("--nc", help="Naming context DN")
    return p.parse_args()


def build_attr_set(oids):
    prefix = []
    partial = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
    partial["dwVersion"] = 1
    partial["cAttrs"] = len(oids)
    for oid in oids:
        partial["rgPartialAttr"].append(drsuapi.MakeAttid(prefix, oid))
    return prefix, partial


def build_dsname(nc_dn):
    dsname = drsuapi.DSNAME()
    dsname["SidLen"] = 0
    dsname["Guid"] = b"\x00" * 16
    dsname["Sid"] = b"\x00" * 16
    dsname["NameLen"] = len(nc_dn)
    dsname["StringName"] = nc_dn
    dsname["structLen"] = len(dsname.getData())
    return dsname


def main():
    args = build_parser()

    if args.attrs is None:
        oids = DEFAULT_ATTRS
    elif args.attrs == ["secret"]:
        oids = DEFAULT_ATTRS
    elif args.attrs == ["non-secret"]:
        oids = NON_SECRET_ATTRS
    else:
        oids = args.attrs

    nc_dn = args.nc
    if nc_dn is None:
        nc_dn = ",".join(f"DC={p}" for p in args.domain.lower().split("."))

    ts_start = datetime.datetime.now(datetime.UTC)
    print(f"TIMESTAMP: {ts_start.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")
    print(f"TARGET: {args.dc}  DOMAIN: {args.domain}  USER: {args.user}")
    print(f"ATTRS: {oids}")
    print(f"NC: {nc_dn}")

    smb = SMBConnection(args.dc, args.dc)
    smb.login(args.user, args.password, args.domain, "", "")

    binding = epm.hept_map(args.dc, drsuapi.MSRPC_UUID_DRSUAPI, protocol="ncacn_ip_tcp")
    rpc_tr = transport.DCERPCTransportFactory(binding)
    rpc_tr.setRemoteHost(args.dc)
    if hasattr(rpc_tr, "set_credentials"):
        rpc_tr.set_credentials(args.user, args.password, args.domain, "", "")
    drsr = rpc_tr.get_dce_rpc()
    drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    drsr.connect()
    drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

    bind_req = drsuapi.DRSBind()
    bind_req["puuidClientDsa"] = drsuapi.NTDSAPI_CLIENT_GUID
    ext = drsuapi.DRS_EXTENSIONS_INT()
    ext["cb"] = len(ext)
    ext["dwFlags"] = (
        drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6
        | drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
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

    dc_info = drsuapi.hDRSDomainControllerInfo(drsr, hdr, args.domain, 2)
    if dc_info["pmsgOut"]["V2"]["cItems"] == 0:
        print(f"FATAL: No DC info for domain {args.domain}")
        sys.exit(1)
    ntds_guid = dc_info["pmsgOut"]["V2"]["rItems"][0]["NtdsDsaObjectGuid"]

    prefix, partial = build_attr_set(oids)
    dsname = build_dsname(nc_dn)

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
    req["pmsgIn"]["V8"]["ulFlags"] = drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
    req["pmsgIn"]["V8"]["cMaxObjects"] = 1
    req["pmsgIn"]["V8"]["cMaxBytes"] = 0
    req["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
    req["pmsgIn"]["V8"]["pPartialAttrSet"] = partial
    req["pmsgIn"]["V8"]["PrefixTableDest"]["PrefixCount"] = len(prefix)
    req["pmsgIn"]["V8"]["PrefixTableDest"]["pPrefixEntry"] = prefix
    req["pmsgIn"]["V8"]["pPartialAttrSetEx1"] = dtypes.NULL

    try:
        resp = drsr.request(req)
        if resp["pmsgOut"]["tag"] >= 6:
            n_objects = resp["pmsgOut"]["V6"]["cNumObjects"]
            print(f"RESULT: SUCCESS  objects_returned={n_objects}")
            for obj in resp["pmsgOut"]["V6"]["pObjects"]["Entinf"]:
                print(f"  Object attributes ({obj['AttrBlock']['attrCount']}):")
                for attr in obj["AttrBlock"]["pAttr"]:
                    aid = attr["attrTyp"]
                    size = len(attr["AttrVal"]["val"]) if attr["AttrVal"] else 0
                    print(f"    attrTyp=0x{aid:05X}  size={size}B")
        else:
            print(f"RESULT: SUCCESS  (tag={resp['pmsgOut']['tag']}, no V6 data)")
    except Exception as exc:
        err_code = getattr(exc, "get_error_code", lambda: None)()
        err_name = ""
        if err_code == 0x20F7:
            err_name = "ERROR_DS_DRA_BAD_DN"
        elif err_code:
            err_name = f"0x{err_code & 0xFFFFFFFF:08X}"
        else:
            err_name = str(exc)[:80]
        print(f"RESULT: FAIL  error={err_name}")

    try:
        drsuapi.hDRSUnbind(drsr, hdr)
    except Exception:
        pass
    drsr.disconnect()
    smb.logoff()

    ts_end = datetime.datetime.now(datetime.UTC)
    print(f"COMPLETED: {ts_end.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z")


if __name__ == "__main__":
    main()
