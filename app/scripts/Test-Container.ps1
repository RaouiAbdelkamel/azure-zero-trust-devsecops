param([string]$Image = 'secure-fastapi:phase2', [int]$Port = 18080)
$ErrorActionPreference = 'Stop'
function Invoke-DockerChecked {
    param([string[]]$DockerArgs)
    $result = & docker @DockerArgs
    if ($LASTEXITCODE -ne 0) { throw 'Docker command failed; validation incomplete.' }
    return $result
}
$null = Invoke-DockerChecked -DockerArgs @('info')
$scriptRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$null = Invoke-DockerChecked -DockerArgs @('build', '-t', $Image, $scriptRoot)
$imageInfo = (Invoke-DockerChecked -DockerArgs @('image', 'inspect', $Image) | ConvertFrom-Json)[0]
if ($imageInfo.Config.User -ne '10001:10001') { throw 'Unexpected image USER' }
if (-not $imageInfo.Config.ExposedPorts.'8080/tcp') { throw '8080 is not exposed' }
if ($imageInfo.Config.Env -match '^(AZURE_CLIENT_SECRET|AZURE_CLIENT_CERTIFICATE_PATH|ARM_CLIENT_SECRET|ARM_ACCESS_KEY)=') {
    throw 'Permanent credential configured in image'
}
$securityOptions = Invoke-DockerChecked -DockerArgs @('info', '--format', '{{json .SecurityOptions}}')
if ($securityOptions -notmatch 'name=seccomp.*profile=builtin') {
    throw 'Docker default seccomp profile is not confirmed; do not mark this check as passed.'
}
$containerName = 'secure-api-check-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
try {
    $null = Invoke-DockerChecked -DockerArgs @('run', '-d', '--name', $containerName,
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
        '--user', '10001:10001', '-e', 'APP_ENV=test',
        '-p', ('127.0.0.1:{0}:8080' -f $Port), $Image)
    # No seccomp override: Docker's confirmed builtin default applies.
    $runtimeCheck = @'
import importlib.util, json, os, pathlib, shutil
assert os.getuid() == 10001 and os.getgid() == 10001
assert 0 not in os.getgroups()
assert not any(shutil.which(name) for name in ('gcc', 'cc', 'g++', 'make'))
assert importlib.util.find_spec('pytest') is None
assert importlib.util.find_spec('bandit') is None
assert importlib.util.find_spec('pip') is None
assert not list(pathlib.Path('/app').rglob('.env*'))
assert not list(pathlib.Path('/app').rglob('*.pem'))
assert not list(pathlib.Path('/app').rglob('*.key'))
status = pathlib.Path('/proc/self/status').read_text()
values = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
assert int(values['CapEff'].strip(), 16) == 0
assert values['NoNewPrivs'].strip() == '1'
assert values['Seccomp'].strip() == '2'
try:
    pathlib.Path('/app/write-probe').write_text('probe')
except OSError:
    pass
else:
    raise AssertionError('Root filesystem is writable')
print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'caps': 0, 'seccomp': 2}))
'@
    $null = Invoke-DockerChecked -DockerArgs @('exec', $containerName, 'python', '-c', $runtimeCheck)
    $info = (Invoke-DockerChecked -DockerArgs @('inspect', $containerName) | ConvertFrom-Json)[0]
    if (-not $info.HostConfig.ReadonlyRootfs) { throw 'Read-only rootfs disabled' }
    $healthy = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $live = Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/health/live' -f $Port)
            $ready = Invoke-RestMethod -Uri ('http://127.0.0.1:{0}/health/ready' -f $Port)
            if ($live.status -eq 'alive' -and $ready.status -eq 'ready') { $healthy = $true; break }
        } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $healthy) { throw 'Health checks failed' }
    $null = Invoke-DockerChecked -DockerArgs @('stop', '--time', '30', $containerName)
    $exitCode = Invoke-DockerChecked -DockerArgs @('inspect', '--format', '{{.State.ExitCode}}', $containerName)
    if ($exitCode -ne '0') { throw 'SIGTERM shutdown did not finish cleanly' }
    Write-Output 'Runtime controls passed. Layer secret scan still requires Trivy (README).'
} finally {
    & docker rm -f $containerName 2>$null | Out-Null
}
