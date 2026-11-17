param(
    [string]$BuildDir = ".\build",
    [int]$HttpPort = 6020,
    [int]$IntervalMs = 2000,
    [string]$TrustStore = "trust_store_fleet.txt",
    [string]$KeyDir = "fleet_keys"
)

$fleet = @(
    @{ Id = "meter-01";   Profile = "power-meter" },
    @{ Id = "plug-kitchen"; Profile = "smart-plug" },
    @{ Id = "climate-living"; Profile = "climate-sensor" },
    @{ Id = "lamp-hall";  Profile = "smart-lamp" },
    @{ Id = "door-front"; Profile = "door-sensor" }
)

New-Item -ItemType Directory -Force -Path $KeyDir | Out-Null
if (Test-Path $TrustStore) { Remove-Item $TrustStore }

$device = Join-Path $BuildDir "device_simulator.exe"
$gateway = Join-Path $BuildDir "gateway_verifier.exe"

foreach ($d in $fleet) {
    & $device --id $d.Id --profile $d.Profile --key-file (Join-Path $KeyDir "$($d.Id).hex") --export-identity $TrustStore | Out-Null
}

Start-Process -FilePath $gateway -ArgumentList "--port", "9443", "--http-port", $HttpPort, "--trust-store", $TrustStore
Start-Sleep -Seconds 2

foreach ($d in $fleet) {
    $deviceArgs = @("--id", $d.Id, "--profile", $d.Profile, "--key-file", (Join-Path $KeyDir "$($d.Id).hex"),
                    "--transport", "http", "--host", "127.0.0.1", "--port", $HttpPort, "--interval", $IntervalMs)
    Start-Process -FilePath $device -ArgumentList $deviceArgs -WindowStyle Hidden
}

Write-Host "Dashboard: http://localhost:$HttpPort"
Write-Host "Stop: Get-Process device_simulator, gateway_verifier | Stop-Process"
