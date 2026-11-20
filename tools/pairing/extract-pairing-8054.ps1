<#
.SYNOPSIS
  Read-only extraction of the Synaptics host-pairing key for Kensington
  VeriMark IT (USB 047d:8054). Does NOT unpair, reset, or modify the sensor
  or Windows Hello. Windows Hello keeps working.

.DESCRIPTION
  1. Searches likely registry locations for a DPAPI-wrapped Synaptics
     PairingData blob (no hardcoded sensor id).
  2. Decrypts it via DPAPI as the correct Windows account (LOCAL SERVICE by
     default; current user as fallback) using a one-shot scheduled task.
  3. Parses the decrypted TagVal container and writes pairing-fields.json.

  Run from an ELEVATED PowerShell (Run as Administrator).

.OUTPUTS
  $OutDir\pairing-fields.json   -- copy this ONE FILE to Linux.
  The work dir under C:\ProgramData holds temp files containing the PRIVATE
  KEY; delete it after copying the JSON.
#>
param(
  [string]$OutDir = "$env:USERPROFILE\Desktop\verimark-8054-pairing"
)

$ErrorActionPreference = 'Stop'
$Work = Join-Path $env:ProgramData 'syna-8054-extract'
$TaskName = 'Syna8054Extract'
$Magic = [byte[]](0x01,0x00,0x00,0x00,0xd0,0x8c,0x9d,0xdf)

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Grant-Work {
  icacls $Work /grant '*S-1-5-19:(OI)(CI)M' 2>$null | Out-Null
  icacls $Work /grant "$([Security.Principal.WindowsIdentity]::GetCurrent().User.Value):(OI)(CI)M" 2>$null | Out-Null
}

function Find-Candidates {
  $curSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $roots = @(
    'Registry::HKEY_USERS\S-1-5-19\Software\Synaptics\PairingData',
    "Registry::HKEY_USERS\$curSid\Software\Synaptics\PairingData",
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Synaptics\PairingData',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Synaptics\PairingData'
  )
  $found = @()
  foreach ($root in $roots) {
    if (-not (Test-Path $root)) { continue }
    try { $key = Get-Item -LiteralPath $root } catch { continue }
    foreach ($name in $key.GetValueNames()) {
      $v = $null
      try { $v = $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames') } catch { continue }
      if ($v -isnot [byte[]] -or $v.Length -lt 24) { continue }
      # Try a few plausible wrapper-header sizes for the DPAPI magic.
      foreach ($off in @(16,0,8,20,24)) {
        if ($v.Length -lt $off + 8) { continue }
        $ok = $true
        for ($i=0; $i -lt 8; $i++) { if ($v[$off+$i] -ne $Magic[$i]) { $ok=$false; break } }
        if ($ok) {
          $found += [pscustomobject]@{
            Root=$root; Name=$name; Blob=$v[($off)..($v.Length-1)]; Offset=$off
          }
          break
        }
      }
    }
  }
  return $found
}

function Parse-TagVal([byte[]]$plain) {
  $entries = @()
  $i = 0
  while ($i + 6 -le $plain.Length) {
    $tag = [BitConverter]::ToUInt16($plain, $i)
    $len = [BitConverter]::ToUInt32($plain, $i + 2)
    if ($len -gt ($plain.Length - $i - 6)) { break }
    $data = New-Object byte[] $len
    [Array]::Copy($plain, $i + 6, $data, 0, $len)
    $entries += [pscustomobject]@{ tag=$tag; len=$len; hex=([BitConverter]::ToString($data) -replace '-','').ToLower() }
    $i += 6 + $len
  }
  return $entries
}

if (-not (Test-Admin)) {
  Write-Error "Run this from an ELEVATED PowerShell (right-click -> Run as Administrator)."
  exit 1
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Grant-Work

Write-Host "[*] Searching registry for Synaptics PairingData blobs..."
$candidates = @(Find-Candidates)
if ($candidates.Count -eq 0) {
  Write-Error "No DPAPI-wrapped PairingData value found. Check that Windows Hello / Synaptics driver is installed and the reader has been used on this Windows install."
  exit 1
}
foreach ($c in $candidates) {
  Write-Host ("    {0} :: {1}  ({2} bytes, header={3})" -f $c.Root, $c.Name, $c.Blob.Length, $c.Offset)
}

# Stage the decrypt helper: runs as the account that owns the DPAPI blob.
$decryptPs = @'
$ErrorActionPreference = 'Stop'
$work = 'WORKDIR_REPLACE'
$inb = Join-Path $work 'dpapi.bin'
$outb = Join-Path $work 'plain.bin'
$errf = Join-Path $work 'plain.bin.err'
try {
  Add-Type -AssemblyName System.Security
  $blob = [IO.File]::ReadAllBytes($inb)
  $plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser')
  [IO.File]::WriteAllBytes($outb, $plain)
} catch {
  Set-Content -Path $errf -Value $_.Exception.Message -NoNewline
}
'@ -replace 'WORKDIR_REPLACE', $Work
$decryptPath = Join-Path $Work 'decrypt.ps1'
[IO.File]::WriteAllText($decryptPath, $decryptPs)

$fieldFile = $null
foreach ($c in $candidates) {
  $fallbackUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  foreach ($principal in @('LOCAL SERVICE', $fallbackUser)) {
    Write-Host ("[*] Trying DPAPI decrypt as '{0}' for {1}..." -f $principal, $c.Name)
    $inb = Join-Path $Work 'dpapi.bin'
    $outb = Join-Path $Work 'plain.bin'
    $errf = Join-Path $Work 'plain.bin.err'
    foreach ($f in @($outb,$errf,$inb)) { if (Test-Path $f) { Remove-Item -Force $f } }
    [IO.File]::WriteAllBytes($inb, $c.Blob)
    Grant-Work

    $cmdline = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $decryptPath
    schtasks /create /tn $TaskName /tr $cmdline /sc once /st 23:59 /ru $principal /rl LIMITED /f 2>$null | Out-Null
    schtasks /run /tn $TaskName 2>$null | Out-Null

    $plain = $null
    for ($n=0; $n -lt 40; $n++) {
      if (Test-Path $outb) { $plain = [IO.File]::ReadAllBytes($outb); break }
      if (Test-Path $errf) {
        $msg = Get-Content $errf -Raw
        Write-Host ("    failed: {0}" -f $msg)
        break
      }
      Start-Sleep -Milliseconds 500
    }
    schtasks /delete /tn $TaskName /f 2>$null | Out-Null
    if ($null -eq $plain) { continue }

    $entries = @(Parse-TagVal $plain)
    $certCount = @($entries | Where-Object { $_.len -eq 400 }).Count
    Write-Host ("[+] decrypted {0} bytes, {1} TagVal entries ({2} x 400-byte certs)" -f $plain.Length, $entries.Count, $certCount)
    if ($certCount -lt 2) { Write-Host "    unexpected layout; trying next candidate"; continue }

    $result = [ordered]@{
      sensor_id   = $c.Name
      registry    = $c.Root
      dpapi_user  = $principal
      plain_len   = $plain.Length
      entries     = $entries
    }
    $fieldFile = Join-Path $OutDir 'pairing-fields.json'
    $result | ConvertTo-Json -Depth 6 | Set-Content -Path $fieldFile -Encoding UTF8
    Write-Host ("[+] wrote {0}" -f $fieldFile)
    break
  }
  if ($fieldFile) { break }
}

if (-not $fieldFile) {
  Write-Error "All decryption attempts failed. Possible causes: DPAPI scope differs from v132; send the registry dump + this script's output for manual analysis."
  exit 1
}

Write-Host ""
Write-Host "SECURITY: pairing-fields.json contains the host PRIVATE KEY."
Write-Host "  1. Copy ONLY pairing-fields.json to Linux."
Write-Host "  2. Delete $Work and any plain.bin / dpapi.bin copies on Windows."
Write-Host "  3. Do NOT run any unpair/reset script."
