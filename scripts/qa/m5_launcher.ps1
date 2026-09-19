param(
    [Parameter(Mandatory = $true)][string]$Distro,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$LauncherArgs
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'M5 QA PowerShell entry requires Windows; use m5_launcher.sh inside WSL.'
}
if (-not $LauncherArgs -or $LauncherArgs.Count -eq 0) {
    throw 'Supply a launcher command; use --help for the command list.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$slashPath = $repoRoot.Replace('\', '/')
$wslRepo = & wsl.exe --distribution $Distro -- wslpath -a $slashPath
if ($LASTEXITCODE -ne 0 -or -not $wslRepo) { throw "Cannot locate repository in WSL distro $Distro." }
$wslRepo = $wslRepo.Trim()

if ($LauncherArgs[0] -eq 'init') {
    if ($LauncherArgs -contains '--source-sha' -or $LauncherArgs -contains '--source-dirty') {
        throw 'PowerShell init supplies Git metadata itself; do not pass source flags.'
    }
    $sourceSha = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sourceSha -notmatch '^[0-9a-f]{40}$') {
        throw 'Cannot read source commit from this repository.'
    }
    $LauncherArgs += @('--source-sha', $sourceSha)
    $dirty = & git -C $repoRoot status --porcelain
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect source worktree status.' }
    if ($dirty) { $LauncherArgs += '--source-dirty' }
}

& wsl.exe --distribution $Distro --cd $wslRepo -- bash "$wslRepo/scripts/qa/m5_launcher.sh" @LauncherArgs
exit $LASTEXITCODE
