<#
.SYNOPSIS
    Host-side automation: run a bash script inside the openEuler guest and get
    its stdout/stderr back. (Experiment 2 - crypto algorithm implementation)

.DESCRIPTION
    Uses SSH with key based authentication (ed25519 key in ~/.ssh/exp2_vm_ed25519),
    so every call is a single connection and the guest output streams straight
    back to the host. An earlier version of this helper drove the guest over
    the VMware backdoor (vmrun copyFileFromHostToGuest); that path froze the
    guest once and is no longer used.

    The guest account is 20241422myh on 192.168.110.131 (openEuler 24.03 LTS-SP4).

    NOTE: this file is intentionally ASCII-only. Windows PowerShell 5.1 reads
    BOM-less .ps1 files as ANSI (GBK), which corrupts non-ASCII text and can
    break parsing. Chinese prose belongs in the .md documents, not here.

.PARAMETER Script
    Bash snippet to execute in the guest.

.PARAMETER ScriptPath
    Path to a local .sh file to execute in the guest (alternative to -Script).

.PARAMETER Sync
    Local directory to copy into the guest at ~/exp2/our (tools/ and scripts/).

.PARAMETER OutHostPath
    Where to store the guest stdout/stderr on the host.
    Default: artifacts/guest-output.txt

.EXAMPLE
    .\scripts\guest.ps1 -Script "uname -a"
#>
[CmdletBinding()]
param(
    [string]$Script,
    [string]$ScriptPath,
    [string]$Sync,
    [string]$OutHostPath,
    [switch]$Fetch
)

$ErrorActionPreference = 'Continue'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$KeyFile  = Join-Path $env:USERPROFILE '.ssh\exp2_vm_ed25519'
$KnownHosts = Join-Path $env:TEMP 'exp2_known_hosts'
$GuestUser = '20241422myh'
$GuestIp   = '192.168.110.131'
$GuestWork = "/home/$GuestUser/exp2"

if (-not (Test-Path $KeyFile)) { throw "SSH key not found: $KeyFile" }

$sshArgs = @(
    '-i', $KeyFile,
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=no',
    "-o", "UserKnownHostsFile=$KnownHosts",
    '-o', 'ConnectTimeout=15',
    '-o', 'LogLevel=ERROR',
    "$GuestUser@$GuestIp"
)

function Invoke-Ssh {
    param([string]$Cmd, [string[]]$Extra = @())
    & ssh @($sshArgs) @Extra $Cmd 2>&1
    return $LASTEXITCODE
}

if ($Sync) {
    if (-not (Test-Path $Sync)) { throw "Sync source not found: $Sync" }
    $tmp = Join-Path $env:TEMP ("exp2sync_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $tar = Join-Path $tmp 'sync.tar.gz'
    Push-Location $Sync
    & tar -czf $tar tools scripts 2>&1 | Out-Null
    Pop-Location
    Write-Host "[ssh] uploading $tar"
    & scp -i $KeyFile -o BatchMode=yes -o StrictHostKeyChecking=no `
          -o "UserKnownHostsFile=$KnownHosts" -o ConnectTimeout=15 -o LogLevel=ERROR $tar `
          "$GuestUser@$GuestIp`:/home/$GuestUser/sync.tar.gz" 2>&1 | Out-Null
    Invoke-Ssh "rm -rf $GuestWork/our/tools $GuestWork/our/scripts && mkdir -p $GuestWork/our && tar xzf /home/$GuestUser/sync.tar.gz -C $GuestWork/our && ls $GuestWork/our" | Out-Null
    Write-Host "[ssh] synced to $GuestWork/our"
}

if ($ScriptPath) {
    if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }
    $Script = Get-Content -LiteralPath $ScriptPath -Raw
}
if (-not $Script) { throw "Provide -Script or -ScriptPath" }

$tmp = Join-Path $env:TEMP ("exp2run_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot 'artifacts') | Out-Null
$sh = Join-Path $tmp 'payload.sh'
[System.IO.File]::WriteAllText($sh, $Script, (New-Object System.Text.UTF8Encoding($false)))

& scp -i $KeyFile -o BatchMode=yes -o StrictHostKeyChecking=no `
      -o "UserKnownHostsFile=$KnownHosts" -o ConnectTimeout=15 -o LogLevel=ERROR $sh `
      "$GuestUser@$GuestIp`:/home/$GuestUser/payload.sh" 2>&1 | Out-Null

Write-Host "[ssh] running..."
$out = & ssh @($sshArgs) "bash /home/$GuestUser/payload.sh 2>&1"
$rc = $LASTEXITCODE

$outHost = if ($OutHostPath) { $OutHostPath } else { Join-Path $RepoRoot 'artifacts\guest-output.txt' }
$text = ($out | Out-String)
[System.IO.File]::WriteAllText($outHost, $text, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[ssh] exit=$rc  output saved: $outHost"
Write-Host "---------------- guest output ----------------"
Write-Host $text
Write-Host "----------------------------------------------"

if ($Fetch) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $tarHost = Join-Path $RepoRoot "artifacts\guest-$stamp.tar.gz"
    & ssh @($sshArgs) "cd $GuestWork && tar czf /home/$GuestUser/bundle.tar.gz our SM2349/src SM2349/*.a SM2349/Makefile 2>/dev/null" 2>&1 | Out-Null
    & scp -i $KeyFile -o BatchMode=yes -o StrictHostKeyChecking=no `
          -o "UserKnownHostsFile=$KnownHosts" -o ConnectTimeout=15 -o LogLevel=ERROR `
          "$GuestUser@$GuestIp`:/home/$GuestUser/bundle.tar.gz" $tarHost 2>&1 | Out-Null
    Write-Host "[ssh] fetched guest bundle: $tarHost"
}
