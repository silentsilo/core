# Everything CI runs, plus the suites that need a real bucket, share or SFTP
# account, against containers on this machine.
#
# Those suites skip themselves when no endpoint is configured, which is the
# right default (nobody should need Docker to run `cargo test`) and also
# means they never ran here: on Windows they were exercised only by CI,
# after a push. This script closes that gap before one.
#
#   .\scripts\test-local.ps1          # start backends, run everything
#   .\scripts\test-local.ps1 -Stop    # tear the containers down again
[CmdletBinding()]
param(
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$compose = Join-Path $root 'docker-compose.test.yml'
# MinIO publishes no images any more, so it is built from source at the
# release CI uses (Go 1.24 or later), once, and run as a plain process.
$minioRelease = 'RELEASE.2025-09-07T16-13-09Z'
$minioHome = Join-Path $root 'target\minio'
$minioDir = Join-Path $minioHome $minioRelease
$minio = Join-Path $minioDir 'minio.exe'
$minioPid = Join-Path $minioHome 'minio.pid'

function Stop-Minio {
    if (Test-Path $minioPid) {
        Stop-Process -Id (Get-Content $minioPid) -Force -ErrorAction SilentlyContinue
        Remove-Item $minioPid
    }
}

if ($Stop) {
    docker compose -f $compose down
    Stop-Minio
    return
}

docker compose -f $compose up -d

if (-not (Test-Path $minio)) {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
        throw 'MinIO is built from source here, and that needs Go 1.24 or later.'
    }
    Write-Host "Building MinIO $minioRelease..."
    $env:GOBIN = $minioDir
    go install "github.com/minio/minio@$minioRelease"
    $built = $LASTEXITCODE
    Remove-Item Env:GOBIN
    if ($built -ne 0) { throw 'Building MinIO failed.' }
}
Stop-Minio
$env:MINIO_ROOT_USER = 'silentsilo'
$env:MINIO_ROOT_PASSWORD = 'silentsilo123'
# Loopback only, so Windows does not ask to open the firewall.
$process = Start-Process -FilePath $minio -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $minioHome 'minio.log') `
    -RedirectStandardError (Join-Path $minioHome 'minio.err') `
    -ArgumentList 'server', (Join-Path $minioHome 'data'),
        '--address', '127.0.0.1:9000', '--console-address', '127.0.0.1:9001'
$process.Id | Set-Content $minioPid

Write-Host 'Waiting for MinIO...'
$ready = $false
foreach ($attempt in 1..30) {
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
            -Uri 'http://127.0.0.1:9000/minio/health/live' | Out-Null
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $ready) { throw 'MinIO did not come up; check target\minio\minio.err.' }

# The bucket the S3 suites expect, created by a signed PUT rather than the
# SDK so a credentials problem shows up here rather than as a puzzling test
# failure. 409 means it is left from an earlier run.
$status = curl.exe -s -o NUL -w '%{http_code}' --aws-sigv4 'aws:amz:us-east-1:s3' `
    --user 'silentsilo:silentsilo123' -X PUT 'http://127.0.0.1:9000/vault-test'
if ($status -ne '200' -and $status -ne '409') { throw "Creating the test bucket failed: HTTP $status" }

$env:SILENTSILO_TEST_S3_ENDPOINT = 'http://127.0.0.1:9000'
$env:SILENTSILO_TEST_S3_KEY = 'silentsilo'
$env:SILENTSILO_TEST_S3_SECRET = 'silentsilo123'
$env:SILENTSILO_TEST_S3_BUCKET = 'vault-test'
$env:SILENTSILO_TEST_WEBDAV_URL = 'http://127.0.0.1:8088'
$env:SILENTSILO_TEST_SFTP_HOST = '127.0.0.1'
$env:SILENTSILO_TEST_SFTP_PORT = '2222'
# Running this script means asking for those suites, so a suite that decides
# to skip itself anyway (a typo above, a container that died mid-run) has to
# fail instead of printing a line nobody reads.
$env:SILENTSILO_TEST_REQUIRE_BACKENDS = '1'

# The real OneDrive, Dropbox and Google Drive test accounts, when this
# machine has them: refresh tokens written by the sign-in example, kept
# outside every repository. A provider not in the file is skipped.
$cloudEnv = Join-Path $env:USERPROFILE '.silentsilo-test\cloud.env'
if (Test-Path $cloudEnv) {
    foreach ($line in Get-Content $cloudEnv) {
        if ($line -match '^\s*(SILENTSILO_TEST_[A-Z_]+)=(.+)$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2].Trim()
        }
    }
}

function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed" }
}

Invoke-Step 'fmt' { cargo fmt --all -- --check }
Invoke-Step 'clippy' { cargo clippy --all-targets --locked -- -D warnings }
# With the endpoints set, this run includes the suites that would otherwise
# skip: the S3 client, the storage contract on every backend, and the sync
# tests that need a real bucket.
Invoke-Step 'cargo test (with real backends)' { cargo test --all --locked }
Invoke-Step 'cargo check' { cargo check --all --locked }

Write-Host "`nAll green. The backends are still up; ./scripts/test-local.ps1 -Stop clears them." -ForegroundColor Green
