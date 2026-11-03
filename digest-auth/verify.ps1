<#
    verify.ps1 - automated end-to-end check for the CVE-2026-73636 Digest lab.

    Builds both targets, runs the capture-replay exploit against each, and asserts
    every expected result from RUNBOOK.md. Prints PASS/FAIL per step and exits 0
    only if all checks pass (non-zero otherwise). Tears down afterwards.

    Requires: Docker Desktop running; Python 3 and curl.exe on PATH (both ship
    with / are standard on Windows 10/11).
    Run from the repository root:
        powershell -ExecutionPolicy Bypass -File digest-auth/verify.ps1

    Note: ErrorActionPreference is intentionally left at 'Continue'. Windows
    PowerShell 5.1 promotes native-command stderr (python, curl.exe, docker) to a
    terminating error under 'Stop', which would abort mid-run; here we check
    results explicitly instead.
#>

$script:pass = 0
$script:fail = 0

function Check {
    param([string]$Name, [bool]$Ok, [string]$Got = '')
    if ($Ok) {
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host ("  FAIL  {0}  (got: {1})" -f $Name, $Got) -ForegroundColor Red
        $script:fail++
    }
}

# Run a native command discarding all output (used for cleanup/teardown).
function Silent { param([string]$Cmd) cmd /c "$Cmd >nul 2>nul" | Out-Null }

# Return the first regex capture group found in $Text, or '' if no match.
# Used to pull each individual HTTP status out of the exploit's output so we
# assert every step separately rather than trusting only the final verdict word.
function Grab { param([string]$Text, [string]$Pattern)
    $m = [regex]::Match($Text, $Pattern)
    if ($m.Success) { $m.Groups[1].Value } else { '' }
}

# Regexes for the three status lines the exploit prints, per step:
#   [1] "    -> authenticated OK (200)"
#   [2] "    -> 401 rejected (stale) - blocked"          (immediate replay)
#   [3] "    -> replay after eviction: 200 accepted ..." (post-eviction replay)
$reCapture = 'authenticated OK \((\d{3})\)'
$reImmediate = '(?m)^\s*->\s*(\d{3})\b'          # bare "-> <code>" = step 2 only
$reEvict = 'replay after eviction:\s*(\d{3})'

# Resolve paths relative to this script so it works from any CWD.
$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$dfVuln   = Join-Path $here 'Dockerfile'
$dfFixed  = Join-Path $here 'Dockerfile69'
$exploit  = Join-Path $here 'exploit.py'

$V = '8068'   # vulnerable target port (mnemonic: 2.4.68)
$P = '8069'   # patched target port    (mnemonic: 2.4.69)

try {
    Write-Host "== Cleaning any previous lab containers ==" -ForegroundColor Cyan
    Silent "docker rm -f digest-vuln digest-fixed"

    # --- Vulnerable target -------------------------------------------------
    Write-Host "== Building and starting the 2.4.68 (vulnerable) target ==" -ForegroundColor Cyan
    Silent ("docker build -t digest-vuln:2.4.68 -f `"{0}`" `"{1}`"" -f $dfVuln, $here)
    Silent ("docker run -d --name digest-vuln -p 127.0.0.1:{0}:80 digest-vuln:2.4.68" -f $V)
    Start-Sleep -Seconds 2

    # Step 2: version + module (B3.1)
    $ver = (docker exec digest-vuln httpd -v 2>$null | Select-Object -First 1)
    Check "2.4.68 target version" ($ver -match '2\.4\.68') $ver
    $mods = (docker exec digest-vuln httpd -M 2>&1 | Out-String)
    Check "auth_digest_module loaded" ($mods -match 'auth_digest_module')

    # Step 3: vulnerable config present (B3.2)
    $conf = (docker exec digest-vuln sh -c "grep -A8 'htdocs/secret' conf/httpd.conf" 2>$null | Out-String)
    Check "AuthDigestNonceLifetime 0 configured" ($conf -match 'AuthDigestNonceLifetime\s+0')

    # Step 4: Digest auth enforced (B3.3)
    $chal = (& curl.exe -s -i "http://127.0.0.1:$V/secret/" 2>$null | Out-String)
    Check "unauthenticated GET challenged (401 Digest)" (($chal -match '401') -and ($chal -match 'WWW-Authenticate:\s*Digest'))
    $authok = (& curl.exe -s -o NUL -w "%{http_code}" --digest -u alice:password123 "http://127.0.0.1:$V/secret/" 2>$null)
    Check "valid Digest credentials accepted (200)" ($authok -eq '200') $authok

    # Step 5: capture-replay bypass on 2.4.68 (B3.4). Assert EACH HTTP status
    # separately, then the exit code, then the verdict word.
    Write-Host "== Running capture-replay exploit against 2.4.68 ==" -ForegroundColor Cyan
    $out68 = (& python "$exploit" --host 127.0.0.1 --port $V 2>&1 | Out-String)
    $rc68  = $LASTEXITCODE
    Write-Host $out68
    $cap68 = Grab $out68 $reCapture
    $imm68 = Grab $out68 $reImmediate
    $evt68 = Grab $out68 $reEvict
    Check "B3.4 step1: simulated capture authenticates (200)" ($cap68 -eq '200') $cap68
    Check "B3.4 step2: immediate replay blocked (401)"        ($imm68 -eq '401') $imm68
    Check "B3.4 step3: replay after eviction ACCEPTED (200)"  ($evt68 -eq '200') $evt68
    Check "B3.4: exploit exit code 0 (VULNERABLE)"            ($rc68 -eq 0) "exit $rc68"
    Check "B3.4: verdict line reports VULNERABLE (BYPASS)"    ($out68 -match 'RESULT: VULNERABLE \(BYPASS\)')

    # --- Patched target ----------------------------------------------------
    Write-Host "== Building and starting the 2.4.69 (patched) target ==" -ForegroundColor Cyan
    Silent ("docker build -t digest-fixed:2.4.69 -f `"{0}`" `"{1}`"" -f $dfFixed, $here)
    Silent ("docker run -d --name digest-fixed -p 127.0.0.1:{0}:80 digest-fixed:2.4.69" -f $P)
    Start-Sleep -Seconds 2

    $ver69 = (docker exec digest-fixed httpd -v 2>$null | Select-Object -First 1)
    Check "D1: 2.4.69 target version" ($ver69 -match '2\.4\.69') $ver69

    # Step 6: same exploit blocked on 2.4.69. Assert EACH HTTP status separately.
    Write-Host "== Running the same exploit against 2.4.69 ==" -ForegroundColor Cyan
    $out69 = (& python "$exploit" --host 127.0.0.1 --port $P 2>&1 | Out-String)
    $rc69  = $LASTEXITCODE
    Write-Host $out69
    $cap69 = Grab $out69 $reCapture
    $imm69 = Grab $out69 $reImmediate
    $evt69 = Grab $out69 $reEvict
    Check "D2: 2.4.69 step1: authentication still works (200)"   ($cap69 -eq '200') $cap69
    Check "D3: 2.4.69 step2: immediate replay blocked (401)"     ($imm69 -eq '401') $imm69
    Check "D3: 2.4.69 step3: replay after eviction blocked (401)" ($evt69 -eq '401') $evt69
    Check "D3: 2.4.69: exploit exit code 2 (NOT VULNERABLE)"     ($rc69 -eq 2) "exit $rc69"
    Check "D3: 2.4.69: verdict line reports NOT VULNERABLE"      ($out69 -match 'RESULT: NOT VULNERABLE')
}
finally {
    Write-Host "== Teardown ==" -ForegroundColor Cyan
    Silent "docker rm -f digest-vuln digest-fixed"
    Silent "docker rmi digest-vuln:2.4.68 digest-fixed:2.4.69"
}

Write-Host ""
$resultColor = 'Green'; if ($script:fail -gt 0) { $resultColor = 'Red' }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $resultColor
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
