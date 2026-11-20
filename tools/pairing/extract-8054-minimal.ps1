<#
  Minimal, read-only extractor for the 047d:8054 Synaptics pairing blob.
  Run ELEVATED on Windows. Writes plain.bin next to this repo's Windows\ folder
  (on the shared D: drive), so Linux can read it without copying files.

  Does NOT unpair, reset, or modify anything on the sensor or Windows Hello.
#>
$ErrorActionPreference = 'Continue'
$repo = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repo 'Windows'
$work = "$env:ProgramData\syna-8054-min"
$task = 'Syna8054MinDecrypt'
$usbSerial = '<USB_SERIAL>'       # from: lsusb -d 047d:8054 -v | grep iSerial
$misSerial = '<MIS_SERIAL_HEX>'      # GET_VERSION bytes 18:24 (6 bytes) + '0000'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_047D&PID_8054\$usbSerial\Device Parameters\synaWudfBioUsb123"
$valueName = $misSerial
$log = Join-Path $outDir 'extract-8054-log.txt'

function Log($m) { "$m" | Tee-Object -FilePath $log -Append }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Content -Path $log -Value "=== extract-8054 $(Get-Date -Format o) ==="

# Make work dir readable by LOCAL SERVICE (SID with '*' prefix for icacls).
icacls $work /grant '*S-1-5-19:(OI)(CI)M' 2>&1 | Out-Null
icacls $work /grant '*S-1-5-18:(OI)(CI)M' 2>&1 | Out-Null

# 1. Read the registry value (binary).
try {
  $key = Get-Item -LiteralPath $regPath -ErrorAction Stop
  $v = $key.GetValue($valueName, $null, 'DoNotExpandEnvironmentNames')
  if ($null -eq $v -or $v.Length -lt 32) { throw "value missing or too short" }
  Log "[+] registry value: $valueName ($($v.Length) bytes)"
} catch {
  Log "[X] registry read failed: $($_.Exception.Message)"
  exit 1
}

# 2. Strip the 16-byte Synaptics wrapper; verify DPAPI magic.
$dpapi = $v[16..($v.Length - 1)]
$magic = [byte[]](0x01,0x00,0x00,0x00,0xd0,0x8c,0x9d,0xdf)
for ($i=0; $i -lt 8; $i++) { if ($dpapi[$i] -ne $magic[$i]) { Log "[X] DPAPI magic mismatch at byte $i"; exit 1 } }
Log "[+] DPAPI blob: $($dpapi.Length) bytes, magic OK"
$inb = Join-Path $work 'dpapi.bin'
[IO.File]::WriteAllBytes($inb, $dpapi)

# 3. Decrypt helper, run as the account that owns the DPAPI key.
$decryptPs = @'
$ErrorActionPreference = 'Stop'
$work = 'WORKDIR'
try {
  Add-Type -AssemblyName System.Security
  $b = [IO.File]::ReadAllBytes((Join-Path $work 'dpapi.bin'))
  $p = [Security.Cryptography.ProtectedData]::Unprotect($b, $null, 'CurrentUser')
  [IO.File]::WriteAllBytes((Join-Path $work 'plain.bin'), $p)
  Set-Content -Path (Join-Path $work 'plain.ok') -Value 'OK' -NoNewline
} catch {
  Set-Content -Path (Join-Path $work 'plain.err') -Value $_.Exception.Message -NoNewline
}
'@ -replace 'WORKDIR', $work
$decryptPath = Join-Path $work 'decrypt.ps1'
[IO.File]::WriteAllText($decryptPath, $decryptPs)
icacls $decryptPath /grant '*S-1-5-19:(OI)(CI)M' 2>&1 | Out-Null

# 4. Try LOCAL SERVICE first (UMDF host account), then current user.
$success = $false
foreach ($principal in @('LOCAL SERVICE', [Security.Principal.WindowsIdentity]::GetCurrent().Name)) {
  Log "[*] decrypt attempt as '$principal'"
  foreach ($f in @('plain.bin','plain.ok','plain.err')) {
    $p = Join-Path $work $f
    if (Test-Path $p) { Remove-Item -Force $p }
  }
  $tr = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $decryptPath
  schtasks /create /tn $task /tr $tr /sc once /st 23:59 /ru $principal /rl LIMITED /f 2>&1 | Out-Null
  schtasks /run /tn $task 2>&1 | Out-Null

  for ($n=0; $n -lt 40; $n++) {
    if (Test-Path (Join-Path $work 'plain.ok')) { $success = $true; break }
    if (Test-Path (Join-Path $work 'plain.err')) {
      Log "[ ] failed: $(Get-Content (Join-Path $work 'plain.err') -Raw)"
      break
    }
    Start-Sleep -Milliseconds 500
  }
  schtasks /delete /tn $task /f 2>&1 | Out-Null
  if ($success) { Log "[+] decrypted as '$principal'"; break }
}

if (-not $success) {
  Log "[X] all decrypt attempts failed"
  exit 1
}

# 5. Copy plaintext to the shared repo folder for Linux to read.
$src = Join-Path $work 'plain.bin'
$dst = Join-Path $outDir 'plain.bin'
Copy-Item -Force $src $dst
Log "[+] wrote $dst ($((Get-Item $dst).Length) bytes)"
Log "DONE - you can boot back into Linux now."
