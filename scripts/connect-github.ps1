<#
.SYNOPSIS
Validate this checkout, commit a checkpoint, and connect its private GitHub repository.
.DESCRIPTION
Run this yourself in an ordinary PowerShell terminal. GitHub CLI may open its
interactive browser login. The script never reads the DeepSeek key or changes ACLs.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,38}$')]
    [string]$Owner = 'pivograd',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')]
    [string]$Name = 'veacode'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Checked {
    param([string]$File, [string[]]$Arguments)
    if ($File -eq $git) {
        # This explicitly selected checkout may have been initialized by Codex's
        # sandbox account. Trust only its exact path for this invocation.
        $Arguments = @('-c', "safe.directory=$($root.Replace('\', '/'))") + $Arguments
    }
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $([IO.Path]::GetFileName($File)) $($Arguments[0]) (exit $LASTEXITCODE)"
    }
}

function Invoke-Captured {
    param([string]$File, [string[]]$Arguments)
    if ($File -eq $git) {
        $Arguments = @('-c', "safe.directory=$($root.Replace('\', '/'))") + $Arguments
    }
    # Windows PowerShell represents native stderr as ErrorRecords. Capture failures
    # explicitly so a missing repository can be distinguished from a network error.
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $File @Arguments 2>&1)
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $oldPreference
    }
    return [pscustomobject]@{
        ExitCode = $code
        Output = (($lines | ForEach-Object { [string]$_ }) -join "`n")
    }
}

function Assert-StagedPaths {
    $result = Invoke-Captured -File $git -Arguments @(
        '-c', 'core.quotepath=false', 'diff', '--cached', '--name-only', '--no-renames', '-z'
    )
    if ($result.ExitCode -ne 0) { throw 'Cannot inspect the Git index.' }
    foreach ($path in ($result.Output -split "`0")) {
        if (-not $path) { continue }
        $top = ($path -split '/', 2)[0]
        if ($allowed -notcontains $top) {
            throw 'The index contains a path outside the publication allowlist. Review staged changes first.'
        }
        if ($path -match '(?i)(^|/)(\.veacode|\.venv|\.git|\.ssh|\.aws|secrets?)(/|$)' -or
            $path -match '(?i)(^|/)(veacode\.local\.toml|\.env(?:\..*)?|id_(?:rsa|ed25519|ecdsa).*|credentials(?:\..*)?|auth\.json)$' -or
            $path -match '(?i)\.(key|pem|p12|pfx|keystore)$') {
            throw 'The index contains a sensitive-looking path. Review staged changes first.'
        }
    }
}

function Assert-Origin {
    foreach ($mode in @(@('--all'), @('--push', '--all'))) {
        $arguments = @('remote', 'get-url') + $mode + @('origin')
        $result = Invoke-Captured -File $git -Arguments $arguments
        if ($result.ExitCode -ne 0) { throw 'Cannot inspect origin fetch/push URLs.' }
        foreach ($url in ($result.Output -split "`r?`n")) {
            if ($url -notmatch '^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+)/([^/]+?)(?:\.git)?/?$' -or
                $Matches[1] -ine $Owner -or $Matches[2] -ine $Name) {
                throw 'Existing origin does not point exclusively to the requested GitHub repository. Nothing was pushed.'
            }
        }
    }
}

function Get-Repository {
    $result = Invoke-Captured -File $gh -Arguments @(
        'repo', 'view', $fullName, '--json', 'nameWithOwner,isPrivate,isEmpty,isArchived,defaultBranchRef'
    )
    if ($result.ExitCode -eq 0) { return ($result.Output | ConvertFrom-Json) }
    if ($result.Output -match 'Could not resolve to a Repository|HTTP 404|\bNot Found\b') {
        return $null
    }
    throw 'GitHub repository lookup failed. Check connectivity and gh authentication before retrying.'
}

$git = (Get-Command git -CommandType Application -ErrorAction Stop).Source
$gh = (Get-Command gh -CommandType Application -ErrorAction Stop).Source
$uv = (Get-Command uv -CommandType Application -ErrorAction Stop).Source
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$fullName = "$Owner/$Name"
$allowed = @(
    '.github', '.gitignore', 'AGENT_ORCHESTRATOR_BRIEF_RU.md', 'README.md',
    'docs', 'examples', 'pyproject.toml', 'uv.lock', 'skills', 'src', 'tests', 'scripts'
)

if ($env:GH_HOST -and $env:GH_HOST -ine 'github.com') {
    throw 'Run with GH_HOST unset or set to github.com.'
}

Push-Location -LiteralPath $root
try {
    $result = Invoke-Captured -File $git -Arguments @('rev-parse', '--show-toplevel')
    if ($result.ExitCode -ne 0) {
        throw "Cannot access this Git repository (exit $($result.ExitCode)). Native Git error: $($result.Output). Run in your ordinary terminal; this script does not change permissions."
    }
    $gitRoot = (Resolve-Path -LiteralPath $result.Output.Trim()).Path
    if ($gitRoot -ine $root) { throw 'The script directory must be the actual Git repository root.' }
    $branch = Invoke-Captured -File $git -Arguments @('symbolic-ref', '--quiet', '--short', 'HEAD')
    if ($branch.ExitCode -ne 0 -or $branch.Output.Trim() -cne 'main') {
        throw 'Expected the local main branch. Switch to main explicitly before running this script.'
    }
    Assert-StagedPaths
    foreach ($path in @('.veacode/deepseek.key', 'veacode.local.toml')) {
        $ignored = Invoke-Captured -File $git -Arguments @('check-ignore', '--quiet', '--', $path)
        if ($ignored.ExitCode -ne 0) {
            throw "Required secret/local path is not safely ignored: $path"
        }
    }
    $remotes = Invoke-Captured -File $git -Arguments @('remote')
    if ($remotes.ExitCode -ne 0) { throw 'Cannot list Git remotes.' }
    $hasOrigin = @($remotes.Output -split "`r?`n") -contains 'origin'
    if ($hasOrigin) { Assert-Origin }

    Invoke-Checked -File $uv -Arguments @('--cache-dir', '.venv/uv-cache', 'sync', '--locked')
    $python = Join-Path $root '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $python = Join-Path $root '.venv/bin/python'
    }
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'uv sync did not provide the local Python interpreter.'
    }
    Invoke-Checked -File $python -Arguments @('-m', 'unittest', 'discover', '-s', 'tests', '-v')
    Invoke-Checked -File $python -Arguments @('-m', 'ruff', 'check', '.')

    $auth = Invoke-Captured -File $gh -Arguments @('auth', 'status', '--hostname', 'github.com')
    if ($auth.ExitCode -ne 0) {
        Invoke-Checked -File $gh -Arguments @(
            'auth', 'login', '--hostname', 'github.com', '--git-protocol', 'https', '--web'
        )
    }
    $identity = Invoke-Captured -File $gh -Arguments @(
        'api', '--hostname', 'github.com', 'user', '--jq', '{login: .login, id: .id}'
    )
    if ($identity.ExitCode -ne 0) { throw 'Cannot verify the signed-in GitHub account.' }
    $account = $identity.Output | ConvertFrom-Json
    if ($account.login -ine $Owner) {
        throw "The active GitHub account must be $Owner. Switch accounts explicitly before retrying."
    }

    $repository = Get-Repository
    if ($null -eq $repository) {
        Invoke-Checked -File $gh -Arguments @('repo', 'create', $fullName, '--private')
        $repository = Get-Repository
    }
    if ($null -eq $repository -or $repository.nameWithOwner -ine $fullName -or
        -not $repository.isPrivate -or $repository.isArchived) {
        throw 'Expected the exact requested private, non-archived repository. Nothing was pushed.'
    }
    if (-not $repository.isEmpty -and -not $hasOrigin) {
        throw 'The existing GitHub repository is not empty and no matching origin was configured. Refusing to combine unrelated histories.'
    }
    if (-not $hasOrigin) {
        Invoke-Checked -File $git -Arguments @('remote', 'add', 'origin', "https://github.com/$fullName.git")
    }
    Assert-Origin
    Invoke-Checked -File $gh -Arguments @('auth', 'setup-git', '--hostname', 'github.com')
    if (-not $repository.isEmpty) {
        Invoke-Checked -File $git -Arguments @('fetch', 'origin', 'refs/heads/main:refs/remotes/origin/main')
        $ancestor = Invoke-Captured -File $git -Arguments @('merge-base', '--is-ancestor', 'origin/main', 'HEAD')
        if ($ancestor.ExitCode -ne 0) {
            throw 'Remote main is not an ancestor of local HEAD. Review the histories manually; no force push is performed.'
        }
    }

    $paths = @()
    foreach ($path in $allowed) {
        $tracked = Invoke-Captured -File $git -Arguments @('ls-files', '--cached', '--', $path)
        if ($tracked.ExitCode -ne 0) { throw 'Cannot inspect tracked publication paths.' }
        if ((Test-Path -LiteralPath (Join-Path $root $path)) -or $tracked.Output) { $paths += $path }
    }
    Invoke-Checked -File $git -Arguments (@('add', '--') + $paths)
    Assert-StagedPaths
    $staged = Invoke-Captured -File $git -Arguments @('diff', '--cached', '--quiet')
    if ($staged.ExitCode -eq 1) {
        $authorName = Invoke-Captured -File $git -Arguments @('config', 'user.name')
        $authorEmail = Invoke-Captured -File $git -Arguments @('config', 'user.email')
        $nameValue = $authorName.Output.Trim()
        $emailValue = $authorEmail.Output.Trim()
        if (-not $nameValue) { $nameValue = $account.login }
        if (-not $emailValue) { $emailValue = "$($account.id)+$($account.login)@users.noreply.github.com" }
        Invoke-Checked -File $git -Arguments @(
            '-c', "user.name=$nameValue", '-c', "user.email=$emailValue",
            'commit', '-m', 'Save Veacode implementation checkpoint'
        )
    }
    elseif ($staged.ExitCode -ne 0) { throw 'Cannot inspect staged changes.' }

    Invoke-Checked -File $git -Arguments @('push', '--set-upstream', 'origin', 'main:main')
    Write-Host "Connected: https://github.com/$fullName (private)"
}
finally {
    Pop-Location
}
