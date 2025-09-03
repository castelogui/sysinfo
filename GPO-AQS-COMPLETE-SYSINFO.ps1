<#
 Inventario-GPO-PerHost.ps1
 - Coleta inventário local
 - Salva 1 JSON por máquina: .\machines\<HOST>.json
 - Atualiza .\manifest.json (SEMPRE um ARRAY)
 - NÃO gera HTML (página é estática e independente)
 Requisitos: Windows PowerShell 5.1 | Recomendo executar como Startup (Computador) / SYSTEM
#>

param(
  [string]$RepoRoot             = ".",

  # Limiares de alerta
  [int]$MinMemFreePercent       = 20,
  [double]$MinMemFreeGB         = 2.0,
  [int]$MinDiskFreePercent      = 15,
  [double]$MinDiskFreeGB        = 20.0,
  [int]$HighTempWarnC           = 80,
  [int]$HighTempCritC           = 90,

  # Lock do manifesto
  [int]$LockMaxTries            = 60,
  [int]$LockSleepMs             = 500,

  [switch]$SkipTemps
)

# ----------------- Helpers -----------------
function New-Dir([string]$Path) {
  try { if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null } } catch {}
}
function Try-Get([scriptblock]$Block) {
  try { $old=$ErrorActionPreference; $ErrorActionPreference='Stop'; & $Block }
  catch { $null } finally { $ErrorActionPreference=$old }
}
function To-GB($bytes) { if ($bytes -ne $null -and $bytes -is [ValueType]) { [math]::Round(([double]$bytes)/1GB,2) } else { $null } }
function Percent($part,$whole){ if (-not $whole -or $whole -eq 0) { return $null } [math]::Round((([double]$part)/([double]$whole))*100,1) }
function Get-UptimeString([datetime]$boot){ if (-not $boot) { return "" } $ts=(Get-Date)-$boot; "{0}d {1}h {2}m" -f $ts.Days,$ts.Hours,$ts.Minutes }
function Acquire-Lock([string]$lockPath,[int]$tries,[int]$sleepMs){
  for($i=0;$i -lt $tries;$i++){
    try { return [System.IO.File]::Open($lockPath,[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None) }
    catch { Start-Sleep -Milliseconds $sleepMs }
  }
  $null
}
function Release-Lock($stream,[string]$lockPath){
  try { if ($stream) { $stream.Close(); $stream.Dispose() } } catch {}
  try { if (Test-Path -LiteralPath $lockPath) { Remove-Item -LiteralPath $lockPath -ErrorAction SilentlyContinue } } catch {}
}
function AtomicWrite-Text([string]$path,[string]$content){
  $tmp = "$path.tmp"; $bak = "$path.bak"
  try {
    $content | Out-File -FilePath $tmp -Encoding utf8 -Force
    if (Test-Path -LiteralPath $path) { Move-Item -LiteralPath $path -Destination $bak -Force -ErrorAction SilentlyContinue }
    Move-Item -LiteralPath $tmp -Destination $path -Force
    if (Test-Path -LiteralPath $bak) { Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue }
  } catch {
    try { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } } catch {}
  }
}
function Get-SeverityWeight([string]$s){ switch ($s) { "Crítico" {2} "Atenção" {1} default {0} } }

# Força JSON ARRAY (mesmo com 1 item) no PS 5.1
function ConvertTo-JsonForceArray {
  param([Parameter(Mandatory)][object]$Collection,[int]$Depth=5)
  if ($Collection -is [System.Collections.IList]) { $arr = $Collection } else { $arr = @($Collection) }
  return ConvertTo-Json -InputObject $arr -Depth $Depth
}

# ----------------- Coleta local -----------------
$computer = $env:COMPUTERNAME

$cs   = Try-Get { Get-CimInstance Win32_ComputerSystem }
$os   = Try-Get { Get-CimInstance Win32_OperatingSystem }
$bios = Try-Get { Get-CimInstance Win32_BIOS }
$bb   = Try-Get { Get-CimInstance Win32_BaseBoard }
$cpu  = Try-Get { Get-CimInstance Win32_Processor }
$ram  = Try-Get { Get-CimInstance Win32_PhysicalMemory }
$gpu  = Try-Get { Get-CimInstance Win32_VideoController }

# Volumes (com fallback)
$vol  = Try-Get { Get-Volume -ErrorAction Stop }
if (-not $vol) {
  $vol = Try-Get { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" } | ForEach-Object {
    [pscustomobject]@{
      DriveLetter     = $_.DeviceID.TrimEnd(':')
      FileSystemLabel = $_.VolumeName
      FileSystem      = $_.FileSystem
      HealthStatus    = $null
      Size            = [double]$_.Size
      SizeRemaining   = [double]$_.FreeSpace
    }
  }
}

# Discos (com fallback) + detecção de TIPO (HDD/SSD/NVMe)
$pd = $null; try { $pd = Get-PhysicalDisk -ErrorAction Stop } catch {}
$dd = Try-Get { Get-CimInstance Win32_DiskDrive }

$discos = @()
if ($pd) {
  $discos = $pd | ForEach-Object {
    $bus = [string]$_.BusType
    $med = [string]$_.MediaType
    $sp  = $_.SpindleSpeed
    $type = if ($bus -match 'NVMe') {'NVMe'}
            elseif ($med -match 'SSD') {'SSD'}
            elseif ($med -match 'HDD') {'HDD'}
            elseif ($sp -ge 1) {'HDD'}
            elseif ($sp -eq 0) {'SSD'}
            else { $null }
    [pscustomobject]@{
      Model    = $_.FriendlyName
      Serial   = $_.SerialNumber
      Media    = $med
      Bus      = $bus
      Type     = $type
      SizeGB   = [math]::Round($_.Size/1GB,2)
      Health   = $_.HealthStatus
      OpStatus = ($_.OperationalStatus -join ', ')
      Spindle  = $_.SpindleSpeed
    }
  }
} elseif ($dd) {
  $discos = $dd | ForEach-Object {
    $bus = [string]$_.InterfaceType
    $model = [string]$_.Model
    $meddd = [string]$_.MediaType
    $type = if ($bus -match 'NVME' -or $model -match 'NVME') {'NVMe'}
            elseif ($model -match 'SSD' -or $meddd -match 'Solid|SSD' -or $model -match 'M\.?2') {'SSD'}
            else { $null } # sem rotação, melhor não chutar HDD
    [pscustomobject]@{
      Model    = $model
      Serial   = $_.SerialNumber
      Media    = if ($meddd) { $meddd } else { $null }
      Bus      = $bus
      Type     = $type
      SizeGB   = [math]::Round($_.Size/1GB,2)
      Health   = $null
      OpStatus = $null
      Spindle  = $null
    }
  }
}

# ----------------- Consolidação de Volumes por Disco -----------------
# Mapeia volumes -> discos físicos para consolidar
$volDiskMap = @{}
try {
    $partitions = Get-CimInstance Win32_DiskPartition
    $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
    $mappings = Get-CimInstance Win32_LogicalDiskToPartition

    foreach ($map in $mappings) {
        $part = ($partitions | Where-Object { $_.DeviceID -eq $map.Antecedent.DeviceID })
        $ld   = ($logicalDisks | Where-Object { $_.DeviceID -eq $map.Dependent.DeviceID })
        if ($part -and $ld) {
            $diskIndex = $part.DiskIndex
            if (-not $volDiskMap.ContainsKey($diskIndex)) {
                $volDiskMap[$diskIndex] = @()
            }
            $volDiskMap[$diskIndex] += $ld
        }
    }
} catch {
    # fallback: se falhar, usa todos os volumes sem consolidar
    $volDiskMap[-1] = $vol
}

# Consolida: pega apenas o volume maior de cada disco
$volumes = @()
foreach ($diskIndex in $volDiskMap.Keys) {
    $vols = $volDiskMap[$diskIndex]
    if ($vols) {
        $largest = $vols | Sort-Object {[double]$_.Size} -Descending | Select-Object -First 1
        $sz  = [double]$largest.Size
        $rem = [double]$largest.FreeSpace
        $volumes += [pscustomobject]@{
            DriveLetter   = $largest.DeviceID.TrimEnd(':')
            Label         = $largest.VolumeName
            FileSystem    = $largest.FileSystem
            SizeGB        = [math]::Round($sz/1GB,2)
            FreeGB        = [math]::Round($rem/1GB,2)
            FreePercent   = if ($sz) { [math]::Round(($rem/$sz)*100,1) } else { $null }
            Health        = $null
        }
    }
}

# RAM módulos (array)
$ramMods = @()
if ($ram) {
  $ramMods = @($ram | ForEach-Object {
    [pscustomobject]@{
      Bank      = $_.BankLabel
      Slot      = $_.DeviceLocator
      Manuf     = $_.Manufacturer
      Part      = $_.PartNumber
      Serial    = $_.SerialNumber
      CapacityGB= [math]::Round($_.Capacity/1GB,2)
      SpeedMHz  = $_.Speed
      ConfClk   = $_.ConfiguredClockSpeed
      Form      = $_.FormFactor
      SMBIOSType= $_.SMBIOSMemoryType
    }
  })
}

# Rede (arrays)
$netCfg = Try-Get { Get-NetIPConfiguration }
$ipv4s=@(); $macs=@()
try { $ipv4s = @($netCfg | ForEach-Object { $_.IPv4Address.IPAddress } | Where-Object { $_ } | Select-Object -Unique) } catch {}
try { $macs = @((Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Where-Object {$_.NetEnabled -eq $true}).MACAddress | Where-Object { $_ } | Select-Object -Unique) } catch {}

# Uptime/CPU
$boot = $os.LastBootUpTime; $uptime = Get-UptimeString $boot
$cpuMain = $cpu | Select-Object -First 1

# Classificação
$warns=@(); $crits=@()
$totalRAM = if ($cs.TotalPhysicalMemory) { To-GB $cs.TotalPhysicalMemory } else { $null }
$freeRAM  = $null; $freeRAMpct = $null
if ($os -and $os.FreePhysicalMemory) {
  $freeRAM = [math]::Round((($os.FreePhysicalMemory*1KB)/1GB),2)
  if ($totalRAM) { $freeRAMpct = Percent $freeRAM $totalRAM }
}
if ($totalRAM -and $freeRAM -ne $null) {
  if ($freeRAMpct -lt 10 -or $freeRAM -lt 1.0) { $crits += "RAM livre muito baixa" }
  elseif ($freeRAMpct -lt $MinMemFreePercent -or $freeRAM -lt $MinMemFreeGB) { $warns += "RAM livre baixa" }
}
$lowDisks = $volumes | Where-Object { $_.FreePercent -lt 10 -or $_.FreeGB -lt 10 }
$warnDisks= $volumes | Where-Object { $_.FreePercent -lt $MinDiskFreePercent -or $_.FreeGB -lt $MinDiskFreeGB }
if ($lowDisks.Count -gt 0) { $crits += "Pouco espaço em disco" }
elseif ($warnDisks.Count -gt 0) { $warns += "Pouco espaço em disco" }

# Temperaturas (best-effort)
$acpiMaxC = $null; $diskMaxC = $null
if (-not $SkipTemps) {
  $acpiTemps = Try-Get { Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' }
  if ($acpiTemps) {
    $maxDeciK = ($acpiTemps | Measure-Object CurrentTemperature -Maximum).Maximum
    if ($maxDeciK) { $acpiMaxC = [math]::Round(($maxDeciK/10) - 273.15,1) }
  }
  $storRel = Try-Get { Get-StorageReliabilityCounter }
  if ($storRel) {
    $t = ($storRel | Where-Object Temperature -ne $null | Measure-Object Temperature -Maximum).Maximum
    if ($t -ne $null) { $diskMaxC = [int]$t }
  }
}
$maxTemp = ($acpiMaxC, $diskMaxC | Where-Object { $_ -ne $null } | Measure-Object -Maximum).Maximum
if ($maxTemp -ne $null) {
  if ($maxTemp -ge $HighTempCritC) { $crits += "Temperatura elevada" }
  elseif ($maxTemp -ge $HighTempWarnC) { $warns += "Temperatura alta" }
}

$Status = if ($crits.Count -gt 0) { "Crítico" } elseif ($warns.Count -gt 0) { "Atenção" } else { "OK" }

# GPU (array)
$gpuArr = @()
if ($gpu) {
  $gpuArr = @($gpu | ForEach-Object {
    [pscustomobject]@{
      Name        = $_.Name
      DriverVer   = $_.DriverVersion
      DriverDate  = $_.DriverDate
      VRAM_GB     = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM/1GB,2) } else { $null }
    }
  })
}

# Objeto deste host
$report = [pscustomobject]@{
  Hostname        = $computer
  TimestampUtc    = (Get-Date).ToUniversalTime().ToString("o")
  Status          = $Status
  IssuesWarn      = @($warns)
  IssuesCrit      = @($crits)
  OS = [pscustomobject]@{
    Caption       = $os.Caption
    Version       = $os.Version
    Build         = $os.BuildNumber
    Architecture  = $os.OSArchitecture
    InstallDate   = $os.InstallDate
    LastBoot      = $boot
    Uptime        = $uptime
  }
  Computer = [pscustomobject]@{
    Manufacturer  = $cs.Manufacturer
    Model         = $cs.Model
    Serial        = $bios.SerialNumber
  }
  BIOS = [pscustomobject]@{
    Vendor        = $bios.Manufacturer
    Version       = $bios.SMBIOSBIOSVersion
    ReleaseDate   = $bios.ReleaseDate
  }
  BaseBoard = [pscustomobject]@{
    Manufacturer  = $bb.Manufacturer
    Product       = $bb.Product
    Serial        = $bb.SerialNumber
  }
  CPU = [pscustomobject]@{
    Name          = $cpuMain.Name
    Cores         = $cpuMain.NumberOfCores
    Logical       = $cpuMain.NumberOfLogicalProcessors
    MaxClockMHz   = $cpuMain.MaxClockSpeed
    ProcessorId   = $cpuMain.ProcessorId
  }
  GPU      = @($gpuArr)
  RAM      = [pscustomobject]@{
    TotalGB       = $totalRAM
    FreeGB        = $freeRAM
    FreePercent   = $freeRAMpct
    Modules       = @($ramMods)
  }
  Storage  = [pscustomobject]@{
    Volumes       = @($volumes)
    Disks         = @($discos)
  }
  Network  = [pscustomobject]@{
    IPv4          = @($ipv4s)
    MACs          = @($macs)
  }
  Temps    = [pscustomobject]@{
    ACPI_MaxC     = $acpiMaxC
    Disk_MaxC     = $diskMaxC
    MaxC          = $maxTemp
  }
}

# ----------------- Persistência por host + manifesto -----------------
$root          = $RepoRoot.TrimEnd('\','/')
$machinesDir   = Join-Path $root "machines"
$manifestPath  = Join-Path $root "manifest.json"
$lockPath      = Join-Path $root ".manifest.lock"
New-Dir $root
New-Dir $machinesDir

# 1) Grava o JSON do host
$hostJsonPath = Join-Path $machinesDir ("{0}.json" -f $computer)
$jsonHost     = ($report | ConvertTo-Json -Depth 12)
AtomicWrite-Text -path $hostJsonPath -content $jsonHost

# 2) Atualiza o manifesto (SEMPRE ARRAY) com lock
$lockStream = Acquire-Lock -lockPath $lockPath -tries $LockMaxTries -sleepMs $LockSleepMs
if ($lockStream) {
  try {
    $manifest = @()
    if (Test-Path -LiteralPath $manifestPath) {
      try {
        $raw = Get-Content -Raw -Path $manifestPath -Encoding UTF8
        $trim = $raw.Trim()
        if     ($trim.StartsWith("[")) { $manifest = $raw | ConvertFrom-Json -ErrorAction Stop }
        elseif ($trim.StartsWith("{")) { $manifest = @($raw | ConvertFrom-Json -ErrorAction Stop) }
      } catch { $manifest = @() }
    }
    if ($manifest -isnot [System.Collections.IList]) { $manifest = @($manifest) }

    $relPath = "machines/{0}.json" -f $computer
    $entry = [pscustomobject]@{
      Hostname     = $computer
      Json         = $relPath
      TimestampUtc = $report.TimestampUtc
      Status       = $report.Status
      OS           = $report.OS.Caption
    }

    $idx = -1
    for ($i=0; $i -lt $manifest.Count; $i++) { if ($manifest[$i].Hostname -eq $computer) { $idx = $i; break } }
    if ($idx -ge 0) { $manifest[$idx] = $entry } else { $manifest += $entry }

    # Ordena por severidade e hostname
    $manifest = @($manifest | Sort-Object @{Expression={Get-SeverityWeight $_.Status}; Descending=$true}, Hostname)

    # Grava como ARRAY
    $manifestJson = ConvertTo-JsonForceArray -Collection $manifest -Depth 6
    AtomicWrite-Text -path $manifestPath -content $manifestJson
  }
  finally { Release-Lock -stream $lockStream -lockPath $lockPath }
}
