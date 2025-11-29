#requires -Version 3.0

<#
    GPO-AQS-COMPLETE-SYSINFO.ps1
    Coleta inventario completo da maquina e salva em JSON com o nome do HOSTNAME.

    Observacoes:
    - Usa Get-CimInstance sempre que possivel.
    - Temperaturas via LibreHardwareMonitorLib.dll, esperada na mesma pasta do script (mesmo em UNC).
      O script copia a DLL para um caminho local antes de carregar.
    - Saida padrao: C:\ProgramData\AQS-Inventory\<HOSTNAME>.json
      Fallback (sem permissao): %TEMP%\AQS-Inventory\<HOSTNAME>.json
    - Datas/horas convertidas para o fuso: (UTC-04:00) Atlantic Standard Time (Canada)
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Timezone alvo: Atlantic Standard Time (UTC-04:00)
try {
    $script:AqsTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById('Atlantic Standard Time')
}
catch {
    # Fallback para timezone local (caso a zona nao exista)
    $script:AqsTimeZone = [System.TimeZoneInfo]::Local
}

function Write-Step {
    param(
        [Parameter(Mandatory)]
        [string]$Message
    )
    Write-Host "[INFO] $Message"
}

#------------------------------------------------------------
# Funcoes auxiliares gerais
#------------------------------------------------------------

function New-AqsInventoryDirectory {
    param(
        [switch]$VerboseOutput
    )

    $targetDir = Join-Path $env:ProgramData 'AQS-Inventory'
    try {
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
            if ($VerboseOutput) {
                Write-Step "Criado diretorio de inventario em: $targetDir"
            }
        }
        else {
            if ($VerboseOutput) {
                Write-Step "Usando diretorio de inventario existente: $targetDir"
            }
        }
    }
    catch {
        $targetDir = Join-Path $env:TEMP 'AQS-Inventory'
        if ($VerboseOutput) {
            Write-Step "Sem permissao em C:\ProgramData. Usando diretorio temporario: $targetDir"
        }
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
        }
    }

    return $targetDir
}

function Convert-BytesToGB {
    param(
        [Parameter(Mandatory)]
        [double]$Bytes,
        [int]$Decimals = 2
    )
    if ($Bytes -le 0) { return 0 }
    return [Math]::Round($Bytes / 1GB, $Decimals)
}

function Convert-CimDateTimeToString {
    param(
        [Parameter(Mandatory)]
        [datetime]$Date
    )
    try {
        $dt = [System.TimeZoneInfo]::ConvertTime($Date, $script:AqsTimeZone)
        return $dt.ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        return $Date.ToString('yyyy-MM-dd HH:mm:ss')
    }
}

function Get-AqsLoggedOnUsers {
    $result = @()
    try {
        $sessions = Get-CimInstance -ClassName Win32_LogonSession |
            Where-Object { $_.LogonType -in 2, 10 }  # Interactive, RemoteInteractive

        foreach ($session in $sessions) {
            $accounts = Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser
            foreach ($acc in $accounts) {
                $user = '{0}\{1}' -f $acc.Domain, $acc.Name
                if ($user -and -not ($result -contains $user)) {
                    $result += $user
                }
            }
        }
    }
    catch {
        # ignora erro, retorna vazio
    }
    return $result
}

function Convert-EdidIdToString {
    param(
        [uint16[]]$IdArray
    )
    if (-not $IdArray) { return $null }

    $chars = $IdArray | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }
    if ($chars) {
        return -join $chars
    }
    return $null
}

function Get-AqsDiskTypeString {
    param(
        [Parameter(Mandatory)]
        $Disk
    )

    $model      = $Disk.Model
    $mediaType  = $Disk.MediaType
    $interface  = $Disk.InterfaceType

    if ($model -match 'NVMe') {
        return 'NVMe SSD'
    }
    elseif ($mediaType -match 'Solid State' -or $model -match 'SSD') {
        if ($interface -match 'USB') { return 'USB SSD' }
        return 'SATA SSD'
    }
    elseif ($mediaType -match 'Removable') {
        return 'Removable'
    }
    else {
        if ($interface -match 'USB') { return 'USB HDD' }
        return 'HDD'
    }
}

function Format-AqsLinkSpeed {
    param(
        [Nullable[UInt64]]$Speed
    )
    if (-not $Speed) { return $null }

    $mbps = [Math]::Round($Speed / 1e6)
    if ($mbps -ge 1000) {
        $gbps = [Math]::Round($mbps / 1000, 2)
        return "{0} Gbps" -f $gbps
    }
    else {
        return "{0} Mbps" -f $mbps
    }
}

function Get-AqsRamType {
    param(
        [uint16]$SmbiosMemoryType,
        [uint16]$MemoryType,
        [int]$SpeedMHz
    )

    $map = @{
        0  = 'Unknown'
        1  = 'Other'
        2  = 'DRAM'
        3  = 'Synchronous DRAM'
        17 = 'SDRAM'
        20 = 'DDR'
        21 = 'DDR2'
        22 = 'DDR2 FB-DIMM'
        24 = 'DDR3'
        26 = 'DDR4'
        34 = 'DDR5'
    }

    $code = 0
    if ($SmbiosMemoryType -and $SmbiosMemoryType -ne 0) {
        $code = $SmbiosMemoryType
    }
    elseif ($MemoryType -and $MemoryType -ne 0) {
        $code = $MemoryType
    }

    if ($code -ne 0 -and $map.ContainsKey($code)) {
        return $map[$code]
    }

    # Fallback heuristico por frequencia
    if (-not $SpeedMHz -or $SpeedMHz -le 0) {
        return 'Unknown'
    }

    if ($SpeedMHz -ge 4000) { return 'DDR5' }
    elseif ($SpeedMHz -ge 2600) { return 'DDR4' }
    elseif ($SpeedMHz -ge 1333) { return 'DDR3' }
    elseif ($SpeedMHz -ge 800)  { return 'DDR2' }
    else { return 'Unknown' }
}

#============================================================
########## CPU ##########
########## CPU ##########
#============================================================

function Get-AqsCpuInfo {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    if (-not $cpu) { return $null }

    return [PSCustomObject]@{
        Name        = $cpu.Name.Trim()
        Cores       = [int]$cpu.NumberOfCores
        Logical     = [int]$cpu.NumberOfLogicalProcessors
        MaxClockMHz = [int]$cpu.MaxClockSpeed
        ProcessorId = $cpu.ProcessorId
    }
}

#============================================================
########## RAM ##########
########## RAM ##########
#============================================================

function Get-AqsRamInfo {
    $modules = Get-CimInstance -ClassName Win32_PhysicalMemory
    if (-not $modules) {
        return [PSCustomObject]@{
            ModuleCount = 0
            Modules     = @()
        }
    }

    $modList = @()
    foreach ($m in $modules) {
        $currentMHz = [int]$m.Speed
        $type = Get-AqsRamType -SmbiosMemoryType $m.SMBIOSMemoryType -MemoryType $m.MemoryType -SpeedMHz $currentMHz

        $capacityGB = Convert-BytesToGB -Bytes ([double]$m.Capacity)
        $configured = [int]$m.ConfiguredClockSpeed
        $maxMHz     = if ($configured -gt 0) { $configured } else { $currentMHz }

        $voltageV = $null
        if ($m.ConfiguredVoltage -gt 0) {
            $voltageV = [Math]::Round($m.ConfiguredVoltage / 1000, 3)
        }

        $modList += [PSCustomObject]@{
            Type          = $type
            CapacityGB    = $capacityGB
            MaxSpeedMHz   = $maxMHz
            CurrentMHz    = $currentMHz
            VoltageV      = $voltageV
            Slot          = $m.DeviceLocator
            Bank          = $m.BankLabel
            Manufacturer  = $m.Manufacturer
            PartNumber    = $m.PartNumber.Trim()
            SerialNumber  = $m.SerialNumber.Trim()
        }
    }

    return [PSCustomObject]@{
        ModuleCount = $modList.Count
        Modules     = $modList
    }
}

#============================================================
########## STORAGE ##########
########## STORAGE ##########
#============================================================

function Get-AqsStorageInfo {
    $volumes = @()
    $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction SilentlyContinue
    foreach ($ld in $logicalDisks) {
        $volumes += [PSCustomObject]@{
            Letter       = $ld.DeviceID
            Label        = $ld.VolumeName
            FileSystem   = $ld.FileSystem
            SizeGB       = Convert-BytesToGB -Bytes ([double]$ld.Size)
            FreeGB       = Convert-BytesToGB -Bytes ([double]$ld.FreeSpace)
        }
    }

    $disks = @()
    $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
    foreach ($disk in $diskDrives) {
        $serial = $disk.SerialNumber
        if (-not $serial) {
            try {
                $media = Get-CimInstance -Query "SELECT * FROM Win32_PhysicalMedia WHERE Tag = '$($disk.DeviceID)'" -ErrorAction SilentlyContinue
                if ($media) {
                    $serial = $media.SerialNumber
                }
            }
            catch { }
        }

        $freeBytes = 0
        $partitions = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition" -ErrorAction SilentlyContinue
        foreach ($part in $partitions) {
            $logDisks = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($part.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition" -ErrorAction SilentlyContinue
            foreach ($ld in $logDisks) {
                try {
                    $freeBytes += [int64]$ld.FreeSpace
                }
                catch { }
            }
        }

        $disks += [PSCustomObject]@{
            Model      = $disk.Model
            Type       = Get-AqsDiskTypeString -Disk $disk
            Interface  = $disk.InterfaceType
            Serial     = ($serial -as [string]).Trim()
            SizeGB     = Convert-BytesToGB -Bytes ([double]$disk.Size)
            FreeGB     = if ($freeBytes -gt 0) { Convert-BytesToGB -Bytes ([double]$freeBytes) } else { $null }
        }
    }

    return [PSCustomObject]@{
        Volumes = $volumes
        Disks   = $disks
    }
}

#============================================================
########## GPU ##########
########## GPU ##########
#============================================================

function Get-AqsGpuInfo {
    # Tenta carregar System.Windows.Forms para obter informacoes das telas
    try { Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop } catch { }

    # Helper em C# para pegar taxa de atualizacao por DISPLAY (EnumDisplaySettings)
    if (-not ('DisplayHelper' -as [type])) {
        $cs = @"
using System;
using System.Runtime.InteropServices;

public static class DisplayHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DEVMODE
    {
        private const int CCHDEVICENAME = 32;
        private const int CCHFORMNAME = 32;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHDEVICENAME)]
        public string dmDeviceName;
        public short  dmSpecVersion;
        public short  dmDriverVersion;
        public short  dmSize;
        public short  dmDriverExtra;
        public int    dmFields;

        public int    dmPositionX;
        public int    dmPositionY;
        public int    dmDisplayOrientation;
        public int    dmDisplayFixedOutput;

        public short  dmColor;
        public short  dmDuplex;
        public short  dmYResolution;
        public short  dmTTOption;
        public short  dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHFORMNAME)]
        public string dmFormName;
        public short  dmLogPixels;
        public int    dmBitsPerPel;
        public int    dmPelsWidth;
        public int    dmPelsHeight;
        public int    dmDisplayFlags;
        public int    dmDisplayFrequency;
        public int    dmICMMethod;
        public int    dmICMIntent;
        public int    dmMediaType;
        public int    dmDitherType;
        public int    dmReserved1;
        public int    dmReserved2;
        public int    dmPanningWidth;
        public int    dmPanningHeight;
    }

    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    public static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

    public static int GetCurrentRefreshRate(string deviceName)
    {
        DEVMODE vDevMode = new DEVMODE();
        vDevMode.dmSize = (short)System.Runtime.InteropServices.Marshal.SizeOf(typeof(DEVMODE));
        if(EnumDisplaySettings(deviceName, -1, ref vDevMode))
        {
            return vDevMode.dmDisplayFrequency;
        }
        return 0;
    }
}
"@
        try { Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue } catch { }
    }

    $gpus = Get-CimInstance -ClassName Win32_VideoController -ErrorAction SilentlyContinue
    $result = @()

    # Lista de monitores logicos (cada DISPLAYX)
    $displayInfos = @()
    try {
        $screens = [System.Windows.Forms.Screen]::AllScreens
        foreach ($scr in $screens) {
            $width  = $scr.Bounds.Width
            $height = $scr.Bounds.Height
            $dev    = $scr.DeviceName  # ex: \\.\DISPLAY1

            $hz = $null
            try {
                if ('DisplayHelper' -as [type]) {
                    $hzVal = [DisplayHelper]::GetCurrentRefreshRate($dev)
                    if ($hzVal -gt 0) { $hz = $hzVal }
                }
            }
            catch { }

            $displayInfos += [PSCustomObject]@{
                DeviceName = $dev
                Resolution = ('{0}x{1}' -f $width, $height)
                RefreshHz  = $hz
            }
        }
    }
    catch { }

    foreach ($gpu in $gpus) {
        $vramGB = if ($gpu.AdapterRAM) {
            Convert-BytesToGB -Bytes ([double]$gpu.AdapterRAM)
        } else { $null }

        $resolution = $null
        if ($gpu.CurrentHorizontalResolution -and $gpu.CurrentVerticalResolution) {
            $resolution = '{0}x{1}' -f $gpu.CurrentHorizontalResolution, $gpu.CurrentVerticalResolution
        }

        $result += [PSCustomObject]@{
            Name           = $gpu.Name
            VRAM_GB        = $vramGB
            Resolution     = $resolution
            RefreshRate    = $gpu.CurrentRefreshRate
            MaxRefreshRate = $gpu.MaxRefreshRate
            Displays       = $displayInfos
        }
    }

    return $result
}

#============================================================
########## MONITOR ##########
########## MONITOR ##########
#============================================================

function Get-AqsMonitorInfo {
    $monitors = @()

    $monId     = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction SilentlyContinue
    $monParams = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue

    foreach ($m in $monId) {
        $params = $monParams | Where-Object { $_.InstanceName -eq $m.InstanceName } | Select-Object -First 1

        $name  = Convert-EdidIdToString -IdArray $m.UserFriendlyName
        $sn    = Convert-EdidIdToString -IdArray $m.SerialNumberID

        $sizeStr = $null
        if ($params.MaxHorizontalImageSize -gt 0 -and $params.MaxVerticalImageSize -gt 0) {
            $hCm = [double]$params.MaxHorizontalImageSize
            $vCm = [double]$params.MaxVerticalImageSize
            $hIn = $hCm / 2.54
            $vIn = $vCm / 2.54
            $diagIn = [Math]::Round([Math]::Sqrt($hIn * $hIn + $vIn * $vIn), 1)
            $sizeStr = '{0}" ({1}x{2} cm)' -f $diagIn, $hCm, $vCm
        }

        $monitors += [PSCustomObject]@{
            Name         = $name
            SerialNumber = $sn
            Size         = $sizeStr
        }
    }

    return [PSCustomObject]@{
        MonitorCount = $monitors.Count
        Monitors     = $monitors
    }
}

#============================================================
########## OS ##########
########## OS ##########
#============================================================

function Get-AqsOsInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    if (-not $os) { return $null }

    $installDate = $os.InstallDate
    $lastBoot    = $os.LastBootUpTime

    $nowLocal = Get-Date
    try {
        $nowAqs  = [System.TimeZoneInfo]::ConvertTime($nowLocal, $script:AqsTimeZone)
        $bootAqs = [System.TimeZoneInfo]::ConvertTime($lastBoot, $script:AqsTimeZone)
    }
    catch {
        $nowAqs  = $nowLocal
        $bootAqs = $lastBoot
    }

    $uptimeSpan = $nowAqs - $bootAqs
    $uptimeStr  = "{0}d {1}h {2}m" -f $uptimeSpan.Days, $uptimeSpan.Hours, $uptimeSpan.Minutes

    return [PSCustomObject]@{
        Name          = $os.Caption
        Version       = $os.Version
        Build         = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        InstallDate   = Convert-CimDateTimeToString -Date $installDate
        LastBoot      = Convert-CimDateTimeToString -Date $lastBoot
        Uptime        = $uptimeStr
    }
}

#============================================================
########## COMPUTER ##########
########## COMPUTER ##########
#============================================================

function Get-AqsComputerInfo {
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

    $users = Get-AqsLoggedOnUsers

    return [PSCustomObject]@{
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        Family       = $cs.SystemFamily
        Serial       = $bios.SerialNumber
        Users        = $users
    }
}

#============================================================
########## BIOS ##########
########## BIOS ##########
#============================================================

function Get-AqsBiosInfo {
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    if (-not $bios) { return $null }

    return [PSCustomObject]@{
        Version = $bios.SMBIOSBIOSVersion
    }
}

#============================================================
########## BASEBOARD ##########
########## BASEBOARD ##########
#============================================================

function Get-AqsBaseBoardInfo {
    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    if (-not $bb) { return $null }

    return [PSCustomObject]@{
        Product = $bb.Product
    }
}

#============================================================
########## NETWORK ##########
########## NETWORK ##########
#============================================================

function Get-AqsNetworkInfo {
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "PhysicalAdapter = True" -ErrorAction SilentlyContinue
    $configs  = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue

    $cfgByIndex = @{}
    foreach ($cfg in $configs) {
        $cfgByIndex[$cfg.Index] = $cfg
    }

    $result = @()
    foreach ($adapter in $adapters) {
        $cfg = $null
        if ($cfgByIndex.ContainsKey($adapter.Index)) {
            $cfg = $cfgByIndex[$adapter.Index]
        }

        $ipv4 = @()
        if ($cfg -and $cfg.IPAddress) {
            $ipv4 = $cfg.IPAddress |
                Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and -not $_.StartsWith('169.254.') }
        }

        $status = if ($adapter.NetEnabled) { 'Connected' } else { 'Disconnected' }

        $result += [PSCustomObject]@{
            AdapterName = $adapter.Name
            Description = $adapter.Description
            MAC         = $adapter.MACAddress
            IPv4        = $ipv4
            Status      = $status
            LinkSpeed   = Format-AqsLinkSpeed -Speed $adapter.Speed
        }
    }

    return [PSCustomObject]@{
        Adapters = $result
    }
}

#============================================================
########## TEMPS ##########
########## TEMPS ##########
#============================================================

function Get-AqsTempsInfo {
    $temps = @{
        Cpu         = @()
        Gpu         = @()
        Memory      = @()
        Motherboard = @()
        Storage     = @()
    }

    try {
        $dllSource = Join-Path $PSScriptRoot 'LibreHardwareMonitorLib.dll'
        if (-not (Test-Path -LiteralPath $dllSource)) {
            Write-Step "DLL LibreHardwareMonitorLib.dll nao encontrada em $PSScriptRoot. Temperaturas serao ignoradas."
            return [PSCustomObject]$temps
        }

        # Copia DLL para caminho local (evita erro de operacao sem suporte em UNC)
        $baseDir = New-AqsInventoryDirectory
        $binDir  = Join-Path $baseDir 'Bin'
        try {
            if (-not (Test-Path -LiteralPath $binDir)) {
                New-Item -Path $binDir -ItemType Directory -Force | Out-Null
            }
        }
        catch {
            $binDir = Join-Path $env:TEMP 'AQS-Inventory-Bin'
            if (-not (Test-Path -LiteralPath $binDir)) {
                New-Item -Path $binDir -ItemType Directory -Force | Out-Null
            }
        }

        $dllLocal = Join-Path $binDir 'LibreHardwareMonitorLib.dll'
        Copy-Item -Path $dllSource -Destination $dllLocal -Force
        try { Unblock-File -Path $dllLocal -ErrorAction SilentlyContinue } catch { }

        Add-Type -Path $dllLocal -ErrorAction Stop

        $comp = New-Object LibreHardwareMonitor.Hardware.Computer
        $comp.IsCpuEnabled         = $true
        $comp.IsGpuEnabled         = $true
        $comp.IsMemoryEnabled      = $true
        $comp.IsMotherboardEnabled = $true
        $comp.IsStorageEnabled     = $true
        $comp.Open()

        # Listas temporarias
        $cpuSensors      = @()
        $gpuSensors      = @()
        $memorySensors   = @()
        $mbSensors       = @()
        $storageSensors  = @()

        foreach ($hw in $comp.Hardware) {
            $allHw = @($hw) + @($hw.SubHardware)
            foreach ($h in $allHw) {
                $h.Update()
                foreach ($sensor in $h.Sensors) {
                    if ($sensor.SensorType.ToString() -ne 'Temperature') { continue }

                    # Ignorar sensores "CPU Core #X Distance to TjMax"
                    if ($h.HardwareType.ToString() -eq 'Cpu' -and $sensor.Name -like '*Distance to TjMax*') {
                        continue
                    }

                    $entry = [PSCustomObject]@{
                        Name  = $sensor.Name
                        Value = [Math]::Round($sensor.Value, 1)
                        Min   = $sensor.Min
                        Max   = $sensor.Max
                        Unit  = 'C'
                    }

                    switch ($h.HardwareType.ToString()) {
                        'Cpu'         { $cpuSensors      += $entry }
                        'GpuAmd'      { $gpuSensors      += $entry }
                        'GpuNvidia'   { $gpuSensors      += $entry }
                        'GpuIntel'    { $gpuSensors      += $entry }
                        'Memory'      { $memorySensors   += $entry }
                        'Motherboard' { $mbSensors       += $entry }
                        'Storage'     { $storageSensors  += $entry }
                        default       { }
                    }
                }
            }
        }

        $comp.Close()

        # CPU: consolidar em apenas UMA media
        if ($cpuSensors.Count -gt 0) {
            $coreAvg = $cpuSensors | Where-Object { $_.Name -eq 'Core Average' } | Select-Object -First 1

            if ($coreAvg) {
                $cpuAvgObj = [PSCustomObject]@{
                    Name  = 'CPU Average'
                    Value = [Math]::Round($coreAvg.Value, 1)
                    Min   = [Math]::Round($coreAvg.Min, 1)
                    Max   = [Math]::Round($coreAvg.Max, 1)
                    Unit  = $coreAvg.Unit
                }
            }
            else {
                $perCore = $cpuSensors | Where-Object { $_.Name -like 'CPU Core #*' }
                if (-not $perCore -or $perCore.Count -eq 0) {
                    $perCore = $cpuSensors
                }

                $avgVal = ($perCore | Measure-Object -Property Value -Average).Average
                $minVal = ($perCore | Measure-Object -Property Min   -Minimum).Minimum
                $maxVal = ($perCore | Measure-Object -Property Max   -Maximum).Maximum

                $cpuAvgObj = [PSCustomObject]@{
                    Name  = 'CPU Average'
                    Value = [Math]::Round($avgVal, 1)
                    Min   = [Math]::Round($minVal, 1)
                    Max   = [Math]::Round($maxVal, 1)
                    Unit  = 'C'
                }
            }

            $temps.Cpu = @($cpuAvgObj)
        }

        $temps.Gpu         = $gpuSensors
        $temps.Memory      = $memorySensors
        $temps.Motherboard = $mbSensors
        $temps.Storage     = $storageSensors
    }
    catch {
        Write-Step "Falha ao coletar temperaturas via LibreHardwareMonitor: $($_.Exception.Message)"
    }

    return [PSCustomObject]$temps
}

#============================================================
########## PROCESSES ##########
########## PROCESSES ##########
#============================================================

function Get-AqsProcessesInfo {
    $procs = @()
    try {
        Get-Process | ForEach-Object {
            $start = $null
            try { $start = $_.StartTime } catch { }

            $procs += [PSCustomObject]@{
                Name          = $_.ProcessName
                Id            = $_.Id
                CpuSeconds    = $_.CPU
                WorkingSetMB  = [Math]::Round($_.WorkingSet64 / 1MB, 2)
                StartTime     = if ($start) { Convert-CimDateTimeToString -Date $start } else { $null }
            }
        }

        # Top 15 combinando CPU e memoria
        $procs = $procs |
            Sort-Object -Property @{Expression='CpuSeconds';Descending=$true},
                                   @{Expression='WorkingSetMB';Descending=$true} |
            Select-Object -First 15
    }
    catch { }

    return $procs
}

#============================================================
########## SOFTWARES ##########
########## SOFTWARES ##########
#============================================================

function Get-AqsSoftwareInfo {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $apps = @()

    foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    $sizeKB = $null
                    if ($_.PSObject.Properties.Name -contains 'EstimatedSize') {
                        $sizeKB = $_.EstimatedSize
                    }

                    $sizeMB = $null
                    if ($sizeKB -and $sizeKB -gt 0) {
                        $sizeMB = [Math]::Round(($sizeKB / 1024), 2)
                    }

                    $apps += [PSCustomObject]@{
                        Name            = $_.DisplayName
                        Version         = $_.DisplayVersion
                        Publisher       = $_.Publisher
                        InstallDate     = $_.InstallDate
                        InstallLocation = $_.InstallLocation
                        SizeMB          = $sizeMB
                        UninstallString = $_.UninstallString
                    }
                }
        }
        catch { }
    }

    Write-Step ("Softwares encontrados (brutos): {0}" -f $apps.Count)

    # Ordena pelos maiores (SizeMB nulo conta como 0) e pega ate 20
    $appsSorted = $apps |
        Sort-Object -Property @{Expression={ if ($_.SizeMB) { $_.SizeMB } else { 0 } };Descending=$true},
                               Name

    $top = $appsSorted | Select-Object -First 20

    # Garante que volte sempre como array (mesmo se tiver 1 unico)
    return ,$top
}

#============================================================
########## EVENTLOGS ##########
########## EVENTLOGS ##########
#============================================================

function Get-AqsEventLogsInfo {
    $logsToCheck = @('System', 'Application')
    $result = @()

    foreach ($logName in $logsToCheck) {
        try {
            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $result += [PSCustomObject]@{
                Name          = $logInfo.LogName
                RecordCount   = $logInfo.RecordCount
                LastWriteTime = Convert-CimDateTimeToString -Date $logInfo.LastWriteTime
                FileSizeMB    = [Math]::Round($logInfo.FileSize / 1MB, 2)
            }
        }
        catch { }
    }

    return $result
}

#============================================================
########## SECURITY ##########
########## SECURITY ##########
#============================================================

function Get-AqsSecurityInfo {
    $avInfo = $null
    if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus
            $lastUpdate = $mp.AntivirusSignatureLastUpdated

            $avInfo = [PSCustomObject]@{
                Product                   = 'Windows Defender'
                AMServiceEnabled          = $mp.AMServiceEnabled
                AntispywareEnabled        = $mp.AntispywareEnabled
                RealTimeProtectionEnabled = $mp.RealTimeProtectionEnabled
                NISEnabled                = $mp.NISEnabled
                SignatureLastUpdated      = if ($lastUpdate) { Convert-CimDateTimeToString -Date $lastUpdate } else { $null }
            }
        }
        catch { }
    }

    $fwProfiles = @()
    if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
        try {
            Get-NetFirewallProfile | ForEach-Object {
                $fwProfiles += [PSCustomObject]@{
                    Name                 = $_.Name
                    Enabled              = $_.Enabled
                    DefaultInboundAction = $_.DefaultInboundAction
                    DefaultOutboundAction= $_.DefaultOutboundAction
                }
            }
        }
        catch { }
    }

    return [PSCustomObject]@{
        Antivirus       = $avInfo
        FirewallProfiles= $fwProfiles
    }
}

#============================================================
########## MAIN ##########
########## MAIN ##########
#============================================================

Write-Step "Iniciando coleta completa de inventario..."

try {
    Write-Step "Iniciando coleta de dados da CPU..."
    $cpu = Get-AqsCpuInfo
    Write-Step "Coleta de dados da CPU concluida."

    Write-Step "Iniciando coleta de dados da RAM..."
    $ram = Get-AqsRamInfo
    Write-Step "Coleta de dados da RAM concluida."

    Write-Step "Iniciando coleta de dados de STORAGE..."
    $storage = Get-AqsStorageInfo
    Write-Step "Coleta de dados de STORAGE concluida."

    Write-Step "Iniciando coleta de dados de GPU..."
    $gpu = Get-AqsGpuInfo
    Write-Step "Coleta de dados de GPU concluida."

    Write-Step "Iniciando coleta de dados de MONITORES..."
    $monitors = Get-AqsMonitorInfo
    Write-Step "Coleta de dados de MONITORES concluida."

    Write-Step "Iniciando coleta de dados do SISTEMA OPERACIONAL..."
    $os = Get-AqsOsInfo
    Write-Step "Coleta de dados do SISTEMA OPERACIONAL concluida."

    Write-Step "Iniciando coleta de dados do COMPUTADOR..."
    $computer = Get-AqsComputerInfo
    Write-Step "Coleta de dados do COMPUTADOR concluida."

    Write-Step "Iniciando coleta de dados da BIOS..."
    $bios = Get-AqsBiosInfo
    Write-Step "Coleta de dados da BIOS concluida."

    Write-Step "Iniciando coleta de dados da PLACA MAE..."
    $baseBoard = Get-AqsBaseBoardInfo
    Write-Step "Coleta de dados da PLACA MAE concluida."

    Write-Step "Iniciando coleta de dados de REDE..."
    $network = Get-AqsNetworkInfo
    Write-Step "Coleta de dados de REDE concluida."

    Write-Step "Iniciando coleta de dados de TEMPERATURAS..."
    $temps = Get-AqsTempsInfo
    Write-Step "Coleta de dados de TEMPERATURAS concluida."

    Write-Step "Iniciando coleta de dados de PROCESSOS..."
    $processes = Get-AqsProcessesInfo
    Write-Step "Coleta de dados de PROCESSOS concluida."

    Write-Step "Iniciando coleta de dados de PROGRAMAS INSTALADOS..."
    $software = Get-AqsSoftwareInfo
    Write-Step "Coleta de dados de PROGRAMAS INSTALADOS concluida."

    Write-Step "Iniciando coleta de dados de LOGS DE EVENTOS..."
    $eventLogs = Get-AqsEventLogsInfo
    Write-Step "Coleta de dados de LOGS DE EVENTOS concluida."

    Write-Step "Iniciando coleta de dados de SEGURANCA..."
    $security = Get-AqsSecurityInfo
    Write-Step "Coleta de dados de SEGURANCA concluida."

    Write-Step "Montando objeto de inventario..."
    $inventory = [ordered]@{
        Hostname   = $env:COMPUTERNAME
        OS         = $os
        Computer   = $computer
        BIOS       = $bios
        BaseBoard  = $baseBoard
        CPU        = $cpu
        GPU        = $gpu
        Monitor    = $monitors
        RAM        = $ram
        Storage    = $storage
        Network    = $network
        Temps      = $temps
        Processes  = $processes
        Softwares  = $software
        EventLogs  = $eventLogs
        Security   = $security
    }

    Write-Step "Convertendo inventario para JSON..."
    $json = $inventory | ConvertTo-Json -Depth 8

    Write-Step "Criando/validando diretorio de saida..."
    $dir  = New-AqsInventoryDirectory -VerboseOutput
    $file = Join-Path $dir ("{0}.json" -f $env:COMPUTERNAME)

    Write-Step "Salvando arquivo de inventario em: $file"
    $json | Out-File -FilePath $file -Encoding UTF8 -Force

    Write-Step "Coleta de inventario concluida com sucesso."
}
catch {
    Write-Step "Erro durante a coleta de inventario: $($_.Exception.Message)"
}
