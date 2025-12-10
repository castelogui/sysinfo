# <#
#  GPO-AQS-COMPLETE-SYSINFO.ps1
#  - Coleta inventário local avançado
#  - Suporte a múltiplos modos de coleta e armazenamento
#  - Persistência histórica e alertas avançados
#  Requisitos: Windows PowerShell 5.1
#>

param(
    [string]$RepoRoot = ".",
    [ValidateSet("Completo", "Minimo")]
    [string]$ModoColeta = "Completo",
    [int]$IntervaloExecucao = 0,
    
    # Limiares de alerta
    [int]$MinMemFreePercent = 20,
    [double]$MinMemFreeGB = 2.0,
    [int]$MinDiskFreePercent = 15,
    [double]$MinDiskFreeGB = 20.0,
    [int]$HighTempWarnC = 80,
    [int]$HighTempCritC = 90,
    [int]$MaxProcessCPU = 90,
    [int]$MaxProcessMemoryMB = 1024,
    
    # Configurações de banco
    [switch]$SkipTemps,
    [switch]$DisableJSON,
    [switch]$EnableRemoteActions,
    
    # Lock do manifesto
    [int]$LockMaxTries = 60,
    [int]$LockSleepMs = 500
)

# ----------------- Configuração inicial -----------------
$ErrorActionPreference = "Stop"
$computer = $env:COMPUTERNAME
# Forçar execução completa (opções desativadas)
$ModoColeta = "Completo"

$scriptVersion = "2.4"

# Caminho da pasta do script (inclui UNC) e da DLL do LibreHardwareMonitor
try {
    $script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
}
catch {
    $script:ScriptRoot = "."
}
$script:LibreHW_DefaultPath = Join-Path -Path $script:ScriptRoot -ChildPath "LibreHardwareMonitorLib.dll"

# ----------------- Helpers melhorados -----------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "ERROR" { Write-Error   $logEntry }
        "WARNING" { Write-Warning $logEntry }
        default { Write-Host    $logEntry }
    }
}

function Test-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function New-Dir([string]$Path) {
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
            Write-Log "Diretório criado: $Path"
        }
    }
    catch {
        Write-Log "Erro ao criar diretório $Path : $($_.Exception.Message)" "ERROR"
    }
}

function Try-Get {
    param(
        [scriptblock]$Block,
        [string]$ErrorMessage = ""
    )
    try {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $result = & $Block
        $ErrorActionPreference = $old
        return $result
    }
    catch {
        if ($ErrorMessage) {
            Write-Log "$ErrorMessage : $($_.Exception.Message)" "WARNING"
        }
        else {
            Write-Log "Falha em operação Try-Get : $($_.Exception.Message)" "WARNING"
        }
        return $null
    }
}

function To-GB($bytes) {
    if ($bytes -ne $null -and $bytes -is [ValueType]) {
        [math]::Round(([double]$bytes) / 1GB, 2)
    }
    else { $null }
}

function Percent($part, $whole) {
    if (-not $whole -or $whole -eq 0) { return $null }
    [math]::Round((([double]$part) / ([double]$whole)) * 100, 1)
}

function Get-UptimeString([datetime]$boot) {
    if (-not $boot) { return "" }
    $ts = (Get-Date) - $boot
    return "{0}d {1}h {2}m" -f $ts.Days, $ts.Hours, $ts.Minutes
}

function Acquire-Lock([string]$lockPath, [int]$tries, [int]$sleepMs) {
    for ($i = 0; $i -lt $tries; $i++) {
        try {
            return [System.IO.File]::Open(
                $lockPath,
                [System.IO.FileMode]::OpenOrCreate,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None
            )
        }
        catch {
            Start-Sleep -Milliseconds $sleepMs
        }
    }
    Write-Log "Não foi possível adquirir o lock: $lockPath" "WARNING"
    return $null
}

function Release-Lock($stream, [string]$lockPath) {
    try {
        if ($stream) {
            $stream.Close()
            $stream.Dispose()
        }
    }
    catch { }
    try {
        if (Test-Path -LiteralPath $lockPath) {
            Remove-Item -LiteralPath $lockPath -ErrorAction SilentlyContinue
        }
    }
    catch { }
}

function AtomicWrite-Text([string]$path, [string]$content) {
    $tmp = "$path.tmp"
    $bak = "$path.bak"
    try {
        $content | Out-File -FilePath $tmp -Encoding utf8 -Force
        if (Test-Path -LiteralPath $path) {
            Move-Item -LiteralPath $path -Destination $bak -Force -ErrorAction SilentlyContinue
        }
        Move-Item -LiteralPath $tmp -Destination $path -Force
        if (Test-Path -LiteralPath $bak) {
            Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        try {
            if (Test-Path -LiteralPath $tmp) {
                Remove-Item -LiteralPath $tmp -Force
            }
        }
        catch { }
        Write-Log "Erro ao escrever arquivo $path : $($_.Exception.Message)" "ERROR"
    }
}

function Get-SeverityWeight([string]$s) {
    switch ($s) {
        "Crítico" { 2 }
        "Atenção" { 1 }
        default { 0 }
    }
}

function ConvertTo-JsonForceArray {
    param(
        [Parameter(Mandatory)]
        [object]$Collection,
        [int]$Depth = 10
    )
    if ($Collection -is [System.Collections.IList]) {
        $arr = $Collection
    }
    else {
        $arr = @($Collection)
    }
    return ConvertTo-Json -InputObject $arr -Depth $Depth
}

function Format-TempDisplay {
    param(
        [Parameter(Mandatory = $false)]
        $Value
    )
    if ($null -eq $Value) {
        return "N/A"
    }
    return ('{0:N1} °C' -f [double]$Value)
}

function Ensure-DisplayHelper {
    if ('DisplayHelper' -as [type]) { return }

    $displayHelperCode = @'
using System;
using System.Runtime.InteropServices;

public static class DisplayHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct DEVMODE
    {
        private const int CCHDEVICENAME = 32;
        private const int CCHFORMNAME = 32;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHDEVICENAME)]
        public string dmDeviceName;
        public ushort dmSpecVersion;
        public ushort dmDriverVersion;
        public ushort dmSize;
        public ushort dmDriverExtra;
        public uint dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public uint dmDisplayOrientation;
        public uint dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCHFORMNAME)]
        public string dmFormName;
        public ushort dmLogPixels;
        public uint dmBitsPerPel;
        public uint dmPelsWidth;
        public uint dmPelsHeight;
        public uint dmDisplayFlags;
        public uint dmDisplayFrequency;
        public uint dmICMMethod;
        public uint dmICMIntent;
        public uint dmMediaType;
        public uint dmDitherType;
        public uint dmReserved1;
        public uint dmReserved2;
        public uint dmPanningWidth;
        public uint dmPanningHeight;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool EnumDisplaySettings(
        string deviceName, int modeNum, ref DEVMODE devMode);

    public static int GetCurrentRefreshRate(string deviceName)
    {
        DEVMODE dm = new DEVMODE();
        dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));
        // -1 = ENUM_CURRENT_SETTINGS
        if (EnumDisplaySettings(deviceName, -1, ref dm))
        {
            return (int)dm.dmDisplayFrequency;
        }
        return 0;
    }

    public static int GetMaxRefreshRate(string deviceName, int width, int height)
    {
        DEVMODE dm = new DEVMODE();
        dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));
        int modeNum = 0;
        int maxFreq = 0;

        while (EnumDisplaySettings(deviceName, modeNum, ref dm))
        {
            if (dm.dmPelsWidth == (uint)width && dm.dmPelsHeight == (uint)height)
            {
                if (dm.dmDisplayFrequency > maxFreq)
                {
                    maxFreq = (int)dm.dmDisplayFrequency;
                }
            }
            modeNum++;
        }
        return maxFreq;
    }
}
'@

    Add-Type -TypeDefinition $displayHelperCode -ErrorAction Stop
}

# ----------------- Integração LibreHardwareMonitor -----------------
function Initialize-LibreHardwareMonitor {
    param(
        [string]$DllPath
    )

    if (-not $DllPath -or [string]::IsNullOrWhiteSpace($DllPath)) {
        $DllPath = $script:LibreHW_DefaultPath
    }

    $dllDir = Split-Path -Parent $DllPath
    $hidPath = Join-Path -Path $dllDir -ChildPath "HidSharp.dll"

    if (-not ("HidSharp.HidDevice" -as [type])) {
        if (Test-Path -LiteralPath $hidPath) {
            try {
                $hidBytes = [System.IO.File]::ReadAllBytes($hidPath)
                [System.Reflection.Assembly]::Load($hidBytes) | Out-Null
                Write-Log ("HidSharp.dll carregada a partir de {0}" -f $hidPath) "INFO"
            }
            catch {
                Write-Log ("Falha ao carregar HidSharp.dll a partir de {0}: {1}" -f $hidPath, $_.Exception.Message) "WARNING"
            }
        }
        else {
            Write-Log ("HidSharp.dll não encontrada em {0}. Algumas leituras de sensores podem falhar." -f $hidPath) "WARNING"
        }
    }

    if ("LibreHardwareMonitor.Hardware.Computer" -as [type]) {
        return $true
    }

    if (-not (Test-Path -LiteralPath $DllPath)) {
        Write-Log "DLL LibreHardwareMonitor não encontrada em: $DllPath" "WARNING"
        return $false
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($DllPath)
        [System.Reflection.Assembly]::Load($bytes) | Out-Null
        Write-Log "LibreHardwareMonitorLib.dll carregada com sucesso a partir de $DllPath." "INFO"
        return $true
    }
    catch {
        Write-Log ("Falha ao carregar LibreHardwareMonitorLib.dll a partir de {0}: {1}" -f $DllPath, $_.Exception.Message) "ERROR"
        return $false
    }
}

function Get-LHMTemperatures {
    param(
        [string]$DllPath
    )

    if (-not (Initialize-LibreHardwareMonitor -DllPath $DllPath)) {
        return [pscustomobject]@{
            CPU       = @{ ValueC = $null; Display = "N/A" }
            GPU       = @{ ValueC = $null; Display = "N/A" }
            RAM       = @{ ValueC = $null; Display = "N/A" }
            Storage   = @{ ValueC = $null; Display = "N/A" }
            Mainboard = @{ ValueC = $null; Display = "N/A" }
            Chipset   = @{ ValueC = $null; Display = "N/A" }
            Sensors   = @()
        }
    }

    $computer = $null

    try {
        $computer = New-Object LibreHardwareMonitor.Hardware.Computer
        $computer.IsCpuEnabled = $true
        $computer.IsGpuEnabled = $true
        $computer.IsMemoryEnabled = $true
        $computer.IsStorageEnabled = $true
        $computer.IsMotherboardEnabled = $true
        $computer.Open()

        $allSensors = @()

        foreach ($hw in $computer.Hardware) {
            $hw.Update()
            foreach ($sub in $hw.SubHardware) { $sub.Update() }

            foreach ($sensor in $hw.Sensors) {
                if ($sensor.SensorType -eq [LibreHardwareMonitor.Hardware.SensorType]::Temperature) {
                    $allSensors += [pscustomobject]@{
                        HardwareName = $hw.Name
                        HardwareType = $hw.HardwareType.ToString()
                        SensorName   = $sensor.Name
                        SensorId     = $sensor.Identifier.ToString()
                        ValueC       = if ($sensor.Value -ne $null) { [math]::Round([double]$sensor.Value, 1) } else { $null }
                        MinC         = if ($sensor.Min -ne $null) { [math]::Round([double]$sensor.Min, 1) } else { $null }
                        MaxC         = if ($sensor.Max -ne $null) { [math]::Round([double]$sensor.Max, 1) } else { $null }
                    }
                }
            }
        }

        function Get-BestSensor {
            param(
                [array]$Candidates,
                [string[]]$NamePriority
            )

            if (-not $Candidates -or $Candidates.Count -eq 0) { return $null }

            if ($NamePriority -and $NamePriority.Count -gt 0) {
                foreach ($pat in $NamePriority) {
                    $hit = $Candidates | Where-Object { $_.SensorName -like $pat } | Select-Object -First 1
                    if ($hit) { return $hit }
                }
            }

            $valid = $Candidates | Where-Object { $_.ValueC -ne $null }
            if ($valid.Count -gt 0) {
                $avg = [math]::Round((($valid | Measure-Object ValueC -Average).Average), 1)
                $minV = ($valid | Measure-Object ValueC -Minimum).Minimum
                $maxV = ($valid | Measure-Object ValueC -Maximum).Maximum
                $first = $valid | Select-Object -First 1

                return [pscustomobject]@{
                    HardwareName = $first.HardwareName
                    HardwareType = $first.HardwareType
                    SensorName   = "Média"
                    SensorId     = $first.SensorId
                    ValueC       = $avg
                    MinC         = $minV
                    MaxC         = $maxV
                }
            }

            return $Candidates | Select-Object -First 1
        }

        $cpuList = $allSensors | Where-Object { $_.HardwareType -eq "Cpu" }
        $gpuList = $allSensors | Where-Object { $_.HardwareType -like "Gpu*" }
        $ramList = $allSensors | Where-Object { $_.HardwareType -eq "Memory" }
        $storList = $allSensors | Where-Object { $_.HardwareType -eq "Storage" }
        $boardList = $allSensors | Where-Object { $_.HardwareType -in @("Motherboard", "Mainboard") }
        $chipList = $allSensors | Where-Object {
            $_.HardwareType -eq "SuperIO" -or
            $_.SensorName -like "*PCH*" -or
            $_.SensorName -like "*Chipset*"
        }

        $bestCpu = Get-BestSensor -Candidates $cpuList   -NamePriority @("CPU Package", "Core Max", "Core Average")
        $bestGpu = Get-BestSensor -Candidates $gpuList   -NamePriority @("GPU Core", "GPU Temperature*", "GPU Hot Spot*")
        $bestRam = Get-BestSensor -Candidates $ramList   -NamePriority @("Memory*", "RAM*")
        $bestStor = Get-BestSensor -Candidates $storList  -NamePriority @("Temperature", "Temperature 1", "Drive Temperature*")
        $bestBoard = Get-BestSensor -Candidates $boardList -NamePriority @("System*", "Motherboard*", "Mainboard*")
        $bestChip = Get-BestSensor -Candidates $chipList  -NamePriority @("*PCH*", "*Chipset*")

        function Make-Summary {
            param([object]$Sensor)

            if ($null -eq $Sensor -or $null -eq $Sensor.ValueC) {
                return @{
                    ValueC  = $null
                    Display = "N/A"
                }
            }

            $val = [math]::Round([double]$Sensor.ValueC, 1)
            return @{
                ValueC  = $val
                Display = ("{0:0.0} °C" -f $val)
            }
        }

        $summarySensors = @()
        foreach ($s in @($bestCpu, $bestGpu, $bestRam, $bestStor, $bestBoard, $bestChip)) {
            if ($s -and $s.ValueC -ne $null) {
                $summarySensors += $s
            }
        }

        return [pscustomobject]@{
            CPU       = (Make-Summary $bestCpu)
            GPU       = (Make-Summary $bestGpu)
            RAM       = (Make-Summary $bestRam)
            Storage   = (Make-Summary $bestStor)
            Mainboard = (Make-Summary $bestBoard)
            Chipset   = (Make-Summary $bestChip)
            Sensors   = @($summarySensors)
        }
    }
    catch {
        Write-Log "Falha ao abrir LibreHardwareMonitor: $($_.Exception.Message)" "WARNING"

        return [pscustomobject]@{
            CPU       = @{ ValueC = $null; Display = "N/A" }
            GPU       = @{ ValueC = $null; Display = "N/A" }
            RAM       = @{ ValueC = $null; Display = "N/A" }
            Storage   = @{ ValueC = $null; Display = "N/A" }
            Mainboard = @{ ValueC = $null; Display = "N/A" }
            Chipset   = @{ ValueC = $null; Display = "N/A" }
            Sensors   = @()
        }
    }
    finally {
        if ($computer) {
            $computer.Close()
        }
    }
}

function Get-BestLHMTempValue {
    param(
        [object[]]$Sensors,
        [string[]]$PreferredPatterns
    )

    if (-not $Sensors -or $Sensors.Count -eq 0) { return $null }

    $valid = $Sensors | Where-Object { $_.ValueC -ne $null }
    if (-not $valid -or $valid.Count -eq 0) { return $null }

    if ($PreferredPatterns -and $PreferredPatterns.Count -gt 0) {
        foreach ($pattern in $PreferredPatterns) {
            $candidate = $valid | Where-Object { $_.SensorName -match $pattern } | Select-Object -First 1
            if ($candidate) { return $candidate.ValueC }
        }
    }

    return ($valid | Measure-Object ValueC -Maximum).Maximum
}

function Get-LHMCategoryTemperatures {
    param(
        [string]$DllPath
    )

    $summary = Get-LHMTemperatures -DllPath $DllPath

    if (-not $summary) {
        return [pscustomobject]@{
            CPU       = $null
            GPU       = $null
            RAM       = $null
            Storage   = $null
            Mainboard = $null
            Chipset   = $null
            Sensors   = @()
        }
    }

    return [pscustomobject]@{
        CPU       = if ($summary.CPU       -and $summary.CPU.ValueC       -ne $null) { [double]$summary.CPU.ValueC }       else { $null }
        GPU       = if ($summary.GPU       -and $summary.GPU.ValueC       -ne $null) { [double]$summary.GPU.ValueC }       else { $null }
        RAM       = if ($summary.RAM       -and $summary.RAM.ValueC       -ne $null) { [double]$summary.RAM.ValueC }       else { $null }
        Storage   = if ($summary.Storage   -and $summary.Storage.ValueC   -ne $null) { [double]$summary.Storage.ValueC }   else { $null }
        Mainboard = if ($summary.Mainboard -and $summary.Mainboard.ValueC -ne $null) { [double]$summary.Mainboard.ValueC } else { $null }
        Chipset   = if ($summary.Chipset   -and $summary.Chipset.ValueC   -ne $null) { [double]$summary.Chipset.ValueC }   else { $null }
        Sensors   = @($summary.Sensors)
    }
}

# ----------------- Coleta de Dados Avançada -----------------
function Get-ProcessInfo {
    Write-Log "Coletando informações de processos"

    try {
        $processes = Get-Process |
        Where-Object { $_.CPU -or $_.WorkingSet } |
        Sort-Object CPU -Descending |
        Select-Object -First 15

        $processInfo = @()
        foreach ($proc in $processes) {
            $startTime = $null
            try { $startTime = $proc.StartTime } catch { }

            $processInfo += [pscustomobject]@{
                Name      = $proc.Name
                ID        = $proc.Id
                CPU       = if ($proc.CPU -ne $null) { [math]::Round($proc.CPU, 2) } else { $null }
                MemoryMB  = [math]::Round(($proc.WorkingSet / 1MB), 2)
                Path      = $proc.Path
                StartTime = $startTime
            }
        }

        return $processInfo
    }
    catch {
        Write-Log "Erro ao coletar informações de processos: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

function Get-ServiceInfo {
    Write-Log "Coletando informações de serviços"

    try {
        $criticalServices = @("WinRM", "Spooler", "EventLog", "LanmanServer", "LanmanWorkstation", "DHCP", "DNS")
        $services = Get-Service -Name $criticalServices -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in $criticalServices }

        $serviceInfo = @()
        foreach ($svc in $services) {
            $startMode = Try-Get {
                (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'").StartMode
            }

            $serviceInfo += [pscustomobject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status
                StartType   = $startMode
            }
        }

        return $serviceInfo
    }
    catch {
        Write-Log "Erro ao coletar informações de serviços: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

function Get-SoftwareInfo {
    Write-Log "Coletando informações de software"

    try {
        $software = @()

        $uninstallPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        foreach ($path in $uninstallPaths) {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName }

            foreach ($item in $items) {
                $sizeMb = $null
                if ($item.PSObject.Properties.Name -contains 'EstimatedSize') {
                    if ($item.EstimatedSize -and $item.EstimatedSize -gt 0) {
                        $sizeMb = [math]::Round(($item.EstimatedSize / 1024), 2)
                    }
                }

                $software += [pscustomobject]@{
                    Name        = $item.DisplayName
                    Version     = $item.DisplayVersion
                    Publisher   = $item.Publisher
                    InstallDate = $item.InstallDate
                    SizeMB      = $sizeMb
                }
            }
        }

        return $software |
        Sort-Object SizeMB -Descending |
        Select-Object -First 20
    }
    catch {
        Write-Log "Erro ao coletar informações de software: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

function Get-EventLogInfo {
    Write-Log "Coletando informações de logs de eventos"

    try {
        $eventLogs = @()
        $startTime = (Get-Date).AddHours(-24)

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application', 'System'
            Level     = 1, 2
            StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if ($events) {
            foreach ($event in $events) {
                $msg = ($event.Message | Out-String)
                $msgShort = $msg.Substring(0, [math]::Min(200, $msg.Length))

                $eventLogs += [pscustomobject]@{
                    TimeCreated = $event.TimeCreated
                    LogName     = $event.LogName
                    Level       = $event.LevelDisplayName
                    Provider    = $event.ProviderName
                    Message     = $msgShort
                    EventID     = $event.Id
                }
            }
        }

        return $eventLogs
    }
    catch {
        Write-Log "Erro ao coletar informações de logs de eventos: $($_.Exception.Message)" "WARNING"
        return @()
    }
}

function Get-SecurityInfo {
    Write-Log "Coletando informações de segurança"

    try {
        $securityInfo = @{
            Antivirus = @()
            Firewall  = @()
        }

        $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            foreach ($av in $antivirus) {
                $isActive = ($av.productState -eq 266240)
                $securityInfo.Antivirus += [pscustomobject]@{
                    Name    = $av.displayName
                    State   = if ($isActive) { "Ativo" } else { "Inativo" }
                    Updated = if ($isActive) { "Atualizado" } else { "Desatualizado" }
                }
            }
        }

        $firewall = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        if ($firewall) {
            foreach ($fw in $firewall) {
                $securityInfo.Firewall += [pscustomobject]@{
                    Profile    = $fw.Name
                    Enabled    = $fw.Enabled
                    DefaultIn  = $fw.DefaultInboundAction
                    DefaultOut = $fw.DefaultOutboundAction
                }
            }
        }

        return $securityInfo
    }
    catch {
        Write-Log "Erro ao coletar informações de segurança: $($_.Exception.Message)" "WARNING"
        return @{}
    }
}

# ----------------- Coleta principal -----------------
function Get-SystemInventory {
    Write-Log "Iniciando coleta de inventário (Modo: $ModoColeta)"

    $cs = Try-Get { Get-CimInstance Win32_ComputerSystem }      "Falha ao coletar informações do sistema"
    $os = Try-Get { Get-CimInstance Win32_OperatingSystem }     "Falha ao coletar informações do OS"
    $bios = Try-Get { Get-CimInstance Win32_BIOS }                "Falha ao coletar informações da BIOS"
    $bb = Try-Get { Get-CimInstance Win32_BaseBoard }           "Falha ao coletar informações da placa-mãe"
    $cpu = Try-Get { Get-CimInstance Win32_Processor }           "Falha ao coletar informações da CPU"
    $ram = Try-Get { Get-CimInstance Win32_PhysicalMemory }      "Falha ao coletar informações da RAM"
    $gpu = Try-Get { Get-CimInstance Win32_VideoController }     "Falha ao coletar informações da GPU"

    # GPU principal (reutilizada para resolução/Hz e resumo)
    $gpuMain = $null
    $gpuResolutionStr = $null
    $gpuCurrentHz = $null
    $gpuMaxHz = $null

    if ($gpu) {
        $gpuMain = $gpu | Select-Object -First 1

        if ($gpuMain.CurrentHorizontalResolution -and $gpuMain.CurrentVerticalResolution) {
            $gpuResolutionStr = '{0}x{1}' -f $gpuMain.CurrentHorizontalResolution, $gpuMain.CurrentVerticalResolution
        }

        if ($gpuMain.CurrentRefreshRate) {
            $gpuCurrentHz = [int]$gpuMain.CurrentRefreshRate
        }
        if ($gpuMain.MaxRefreshRate) {
            $gpuMaxHz = [int]$gpuMain.MaxRefreshRate
        }
    }

    # Coletas condicionais
    $processInfo = if ($ModoColeta -ne "Minimo") { Get-ProcessInfo }  else { @() }
    $serviceInfo = if ($ModoColeta -ne "Minimo") { Get-ServiceInfo }  else { @() }
    $softwareInfo = if ($ModoColeta -eq "Completo") { Get-SoftwareInfo } else { @() }
    $eventLogInfo = if ($ModoColeta -eq "Completo") { Get-EventLogInfo } else { @() }
    $securityInfo = if ($ModoColeta -eq "Completo") { Get-SecurityInfo } else { @{} }

    # Storage
    $vol = Try-Get { Get-Volume -ErrorAction Stop } "Falha ao coletar informações de volume"
    if (-not $vol) {
        $vol = Try-Get {
            Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        } "Falha ao coletar informações de disco lógico" | ForEach-Object {
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

    $pd = $null
    try { $pd = Get-PhysicalDisk -ErrorAction Stop } catch { }
    $dd = Try-Get { Get-CimInstance Win32_DiskDrive } "Falha ao coletar informações de disco"

    $discos = @()
    if ($pd) {
        $discos = $pd | ForEach-Object {
            $bus = [string]$_.BusType
            $med = [string]$_.MediaType
            $sp = $_.SpindleSpeed
            $type = if ($bus -match 'NVMe') { 'NVMe' }
            elseif ($med -match 'SSD') { 'SSD' }
            elseif ($med -match 'HDD') { 'HDD' }
            elseif ($sp -ge 1) { 'HDD' }
            elseif ($sp -eq 0) { 'SSD' }
            else { $null }
            [pscustomobject]@{
                Model    = $_.FriendlyName
                Serial   = $_.SerialNumber
                Media    = $med
                Bus      = $bus
                Type     = $type
                SizeGB   = [math]::Round($_.Size / 1GB, 2)
                Health   = $_.HealthStatus
                OpStatus = ($_.OperationalStatus -join ', ')
                Spindle  = $_.SpindleSpeed
            }
        }
    }
    elseif ($dd) {
        $discos = $dd | ForEach-Object {
            $bus = [string]$_.InterfaceType
            $model = [string]$_.Model
            $meddd = $null
            if ($_.PSObject.Properties.Name -contains 'MediaType') {
                $meddd = [string]$_.MediaType
            }
            $type = if ($bus -match 'NVME' -or $model -match 'NVME') { 'NVMe' }
            elseif ($model -match 'SSD' -or $meddd -match 'Solid|SSD' -or $model -match 'M\.?2') { 'SSD' }
            else { $null }
            [pscustomobject]@{
                Model    = $model
                Serial   = $_.SerialNumber
                Media    = $meddd
                Bus      = $bus
                Type     = $type
                SizeGB   = [math]::Round($_.Size / 1GB, 2)
                Health   = $null
                OpStatus = $null
                Spindle  = $null
            }
        }
    }

    $volumes = @()
    if ($vol) {
        foreach ($v in $vol) {
            $sz = [double]$v.Size
            if (-not $sz -or $sz -le 0) { continue }

            $sizeGB = [math]::Round($sz / 1GB, 2)

            $driveLetter = $null
            $label = $null
            $fs = $null
            $health = $null

            if ($v.PSObject.Properties.Name -contains 'DriveLetter') {
                if ($v.DriveLetter) {
                    $driveLetter = $v.DriveLetter.ToString().TrimEnd(':')
                }
            }
            elseif ($v.PSObject.Properties.Name -contains 'DeviceID') {
                $driveLetter = $v.DeviceID.TrimEnd(':')
            }

            if ($v.PSObject.Properties.Name -contains 'FileSystemLabel') {
                $label = $v.FileSystemLabel
            }
            elseif ($v.PSObject.Properties.Name -contains 'VolumeName') {
                $label = $v.VolumeName
            }

            if ($v.PSObject.Properties.Name -contains 'FileSystem') {
                $fs = $v.FileSystem
            }

            if ($v.PSObject.Properties.Name -contains 'HealthStatus') {
                $health = $v.HealthStatus
            }

            $hasLetter = -not [string]::IsNullOrWhiteSpace($driveLetter)
            if (-not $hasLetter -and $sizeGB -lt 10) {
                continue
            }

            $rem = [double]$v.SizeRemaining

            $volumes += [pscustomobject]@{
                DriveLetter = $driveLetter
                Label       = $label
                FileSystem  = $fs
                SizeGB      = $sizeGB
                FreeGB      = [math]::Round($rem / 1GB, 2)
                FreePercent = if ($sz) { [math]::Round(($rem / $sz) * 100, 1) } else { $null }
                Health      = $health
            }
        }
    }

    # RAM módulos
    $ramMods = @()
    if ($ram) {
        $ramMods = @(
            $ram | ForEach-Object {
                [pscustomobject]@{
                    Bank        = $_.BankLabel
                    Slot        = $_.DeviceLocator
                    Manuf       = $_.Manufacturer
                    Part        = $_.PartNumber
                    Serial      = $_.SerialNumber
                    CapacityGB  = [math]::Round($_.Capacity / 1GB, 2)
                    SpeedMHz    = $_.Speed
                    ConfClk     = $_.ConfiguredClockSpeed
                    Form        = $_.FormFactor
                    SMBIOSType  = $_.SMBIOSMemoryType
                    Voltage     = [math]::Round($_.ConfiguredVoltage / 1000, 2)
                    Min_Voltage = [math]::Round($_.MinVoltage / 1000, 2)
                    Max_Voltage = [math]::Round($_.MaxVoltage / 1000, 2)
                }
            }
        )
    }

    # Monitores (EDID + Hz por tela + primário)
    $monitors = @()
    $screenInfo = @()

    try {
        $ids = Try-Get { Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID }                  "Falha ao coletar informações de monitor"
        $basic = Try-Get { Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams } "Falha ao coletar parâmetros básicos de monitor"

        if ($ids) {
            $decode = {
                param([uint16[]]$u16)
                if (-not $u16) { return $null }
                -join ([char[]]($u16 | Where-Object { $_ -ne 0 }))
            }

            foreach ($m in @($ids | ForEach-Object { $_ })) {
                if ($m.PSObject.Properties.Name -contains 'Active') {
                    if (-not $m.Active) { continue }
                }

                $b = $basic | Where-Object InstanceName -eq $m.InstanceName

                $w = 0.0
                $h = 0.0
                if ($b) {
                    $w = [double]$b.MaxHorizontalImageSize
                    $h = [double]$b.MaxVerticalImageSize
                }

                $diag = $null
                if ($w -gt 0 -and $h -gt 0) {
                    $diag = [math]::Round(
                        [math]::Sqrt(
                            [math]::Pow($w / 2.54, 2) +
                            [math]::Pow($h / 2.54, 2)
                        ),
                        1
                    )
                }

                $inputType = $null
                if ($b -and ($b.PSObject.Properties.Name -contains 'VideoInputType')) {
                    $inputType = if ($b.VideoInputType) { 'Digital' } else { 'Analógica' }
                }

                $monitors += [pscustomobject]@{
                    Manufacturer = (& $decode $m.ManufacturerName)
                    Name         = (& $decode $m.UserFriendlyName)
                    Model        = (& $decode $m.ProductCodeID)
                    Serial       = (& $decode $m.SerialNumberID)
                    Week         = $m.WeekOfManufacture
                    Year         = $m.YearOfManufacture
                    SizeInches   = $diag
                    WidthCm      = if ($w) { [int]$w } else { $null }
                    HeightCm     = if ($h) { [int]$h } else { $null }
                    Input        = $inputType
                    InstanceName = $m.InstanceName

                    WidthPx      = $null
                    HeightPx     = $null
                    Resolution   = $null
                    CurrentHz    = $null
                    MaxHz        = $null
                    Primary      = $false
                }
            }
        }
    }
    catch {
        Write-Log "Erro ao coletar informações de monitores (EDID): $($_.Exception.Message)" "WARNING"
    }

    # Tenta obter resolução e primário via System.Windows.Forms.Screen
    try {
        [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        if ([System.Windows.Forms.Screen] -as [type]) {
            $screensDotNet = [System.Windows.Forms.Screen]::AllScreens
            $screenInfo = @(
                for ($i = 0; $i -lt $screensDotNet.Count; $i++) {
                    [pscustomobject]@{
                        Index      = $i
                        Primary    = $screensDotNet[$i].Primary
                        WidthPx    = $screensDotNet[$i].Bounds.Width
                        HeightPx   = $screensDotNet[$i].Bounds.Height
                        DeviceName = $screensDotNet[$i].DeviceName   # Ex: \\.\DISPLAY1
                        Resolution = ('{0}x{1}' -f $screensDotNet[$i].Bounds.Width, $screensDotNet[$i].Bounds.Height)
                    }
                }
            )
        }
        else {
            $screenInfo = @()
        }
    }
    catch {
        $screenInfo = @()
    }

    # Usa DisplayHelper (Win32 API) para obter Hz por tela
    if ($screenInfo.Count -gt 0) {
        Ensure-DisplayHelper
    }

    if ($monitors.Count -gt 0) {
        for ($i = 0; $i -lt $monitors.Count; $i++) {
            $mon = $monitors[$i]
            $scr = if ($screenInfo.Count -gt $i) { $screenInfo[$i] } else { $null }

            if ($scr) {
                $mon.WidthPx = $scr.WidthPx
                $mon.HeightPx = $scr.HeightPx
                $mon.Resolution = $scr.Resolution
                $mon.Primary = $scr.Primary

                # Hz atuais para essa tela
                try {
                    $hz = [DisplayHelper]::GetCurrentRefreshRate($scr.DeviceName)
                }
                catch {
                    $hz = 0
                }
                if ($hz -gt 0) {
                    $mon.CurrentHz = $hz
                }

                # Hz máximos (para essa resolução)
                try {
                    $maxHz = [DisplayHelper]::GetMaxRefreshRate($scr.DeviceName, $scr.WidthPx, $scr.HeightPx)
                }
                catch {
                    $maxHz = 0
                }
                if ($maxHz -gt 0) {
                    $mon.MaxHz = $maxHz
                }
            }
            elseif ($gpuResolutionStr) {
                # fallback caso não tenha Screen mapeada
                $parts = $gpuResolutionStr -split 'x'
                if ($parts.Count -eq 2) {
                    $mon.WidthPx = [int]$parts[0]
                    $mon.HeightPx = [int]$parts[1]
                    $mon.Resolution = $gpuResolutionStr
                }
            }
        }

        # Se ainda assim ninguém estiver marcado como primário, força o primeiro
        if (-not ($monitors | Where-Object { $_.Primary } | Select-Object -First 1)) {
            $monitors[0].Primary = $true
        }
    }


    # Rede
    $netCfg = Try-Get { Get-NetIPConfiguration } "Falha ao coletar configuração de rede"
    $ipv4s = @()
    $macs = @()

    try {
        $ipv4s = @(
            $netCfg |
            ForEach-Object { $_.IPv4Address.IPAddress } |
            Where-Object { $_ } |
            Select-Object -Unique
        )
    }
    catch { }

    try {
        $macs = @(
            Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" |
            Where-Object { $_.NetEnabled -eq $true } |
            ForEach-Object { $_.MACAddress } |
            Where-Object { $_ } |
            Select-Object -Unique
        )
    }
    catch { }

    $adapters = Try-Get { Get-NetAdapter -Physical } "Falha ao coletar adaptadores de rede"
    $nicDetails = @()

    if ($adapters) {
        foreach ($na in $adapters) {
            $alias = $na.Name

            $ipsForAlias = @()
            try {
                $ipsForAlias = @(
                    $netCfg |
                    Where-Object { $_.InterfaceAlias -eq $alias } |
                    ForEach-Object { $_.IPv4Address.IPAddress } |
                    Where-Object { $_ }
                )
            }
            catch { }

            $speedHuman = $na.LinkSpeed
            if (-not $speedHuman -or $speedHuman -eq '0 bps') {
                try {
                    $wmi = Get-CimInstance Win32_NetworkAdapter -Filter "NetEnabled=True AND PhysicalAdapter=True" |
                    Where-Object { $_.PNPDeviceID -eq $na.PnPDeviceID }

                    $bps = $wmi.Speed
                    if ($bps) {
                        if ($bps -ge 1e9) { $speedHuman = ('{0:N0} Gbps' -f ($bps / 1e9)) }
                        elseif ($bps -ge 1e6) { $speedHuman = ('{0:N0} Mbps' -f ($bps / 1e6)) }
                        elseif ($bps -ge 1e3) { $speedHuman = ('{0:N0} Kbps' -f ($bps / 1e3)) }
                        else { $speedHuman = ('{0} bps' -f $bps) }
                    }
                }
                catch { }
            }

            $nicDetails += [pscustomobject]@{
                Name   = $alias
                Status = $na.Status
                MAC    = $na.MacAddress
                IPv4   = $ipsForAlias
                Speed  = $speedHuman
            }
        }
    }

    # Uptime/CPU
    $boot = $os.LastBootUpTime
    $uptime = Get-UptimeString $boot
    $cpuMain = $cpu | Select-Object -First 1

    # Temperaturas
    $acpiMaxC = $null
    $diskMaxC = $null
    $lhmSummary = [pscustomobject]@{
        CPU       = $null
        GPU       = $null
        RAM       = $null
        Storage   = $null
        Mainboard = $null
        Chipset   = $null
        Sensors   = @()
    }

    if (-not $SkipTemps) {
        $acpiTemps = Try-Get {
            Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature'
        } "Falha ao coletar temperaturas ACPI"
        if ($acpiTemps) {
            $maxDeciK = ($acpiTemps | Measure-Object CurrentTemperature -Maximum).Maximum
            if ($maxDeciK) { $acpiMaxC = [math]::Round(($maxDeciK / 10) - 273.15, 1) }
        }

        $storRel = Try-Get {
            try {
                Get-StorageReliabilityCounter -ErrorAction Stop | Where-Object { $_.Temperature -ne $null }
            }
            catch {
                Get-CimInstance -Namespace root\microsoft\windows\storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.Temperature -ne $null }
            }
        } "Falha ao coletar contadores de armazenamento"

        if ($storRel) {
            $t = ($storRel | Where-Object Temperature -ne $null | Measure-Object Temperature -Maximum).Maximum
            if ($t -ne $null) { $diskMaxC = [int]$t }
        }

        $lhmSummary = Get-LHMCategoryTemperatures -DllPath $script:LibreHW_DefaultPath
    }

    $tempsArray = @()
    if ($acpiMaxC -ne $null) { $tempsArray += $acpiMaxC }
    if ($diskMaxC -ne $null) { $tempsArray += $diskMaxC }

    foreach ($v in @(
            $lhmSummary.CPU,
            $lhmSummary.GPU,
            $lhmSummary.RAM,
            $lhmSummary.Storage,
            $lhmSummary.Mainboard,
            $lhmSummary.Chipset
        )) {
        if ($v -ne $null) { $tempsArray += $v }
    }

    $maxTemp = if ($tempsArray.Count -gt 0) { ($tempsArray | Measure-Object -Maximum).Maximum } else { $null }

    # Verificação de alertas
    $warns = @()
    $crits = @()

    $totalRAM = if ($cs.TotalPhysicalMemory) { To-GB $cs.TotalPhysicalMemory } else { $null }
    $freeRAM = $null
    $freeRAMpct = $null

    if ($os -and $os.FreePhysicalMemory) {
        $freeRAM = [math]::Round((($os.FreePhysicalMemory * 1KB) / 1GB), 2)
        if ($totalRAM) { $freeRAMpct = Percent $freeRAM $totalRAM }
    }

    if ($totalRAM -and $freeRAM -ne $null) {
        if ($freeRAMpct -lt 10 -or $freeRAM -lt 1.0) {
            $crits += "RAM livre muito baixa"
        }
        elseif ($freeRAMpct -lt $MinMemFreePercent -or $freeRAM -lt $MinMemFreeGB) {
            $warns += "RAM livre baixa"
        }
    }

    $lowDisks = $volumes | Where-Object { $_.FreePercent -lt 10 -or $_.FreeGB -lt 10 }
    $warnDisks = $volumes | Where-Object { $_.FreePercent -lt $MinDiskFreePercent -or $_.FreeGB -lt $MinDiskFreeGB }
    if ($lowDisks.Count -gt 0) {
        $crits += "Pouco espaço em disco"
    }
    elseif ($warnDisks.Count -gt 0) {
        $warns += "Pouco espaço em disco"
    }

    if ($maxTemp -ne $null) {
        if ($maxTemp -ge $HighTempCritC) {
            $crits += "Temperatura elevada"
        }
        elseif ($maxTemp -ge $HighTempWarnC) {
            $warns += "Temperatura alta"
        }
    }

    if ($processInfo) {
        $highCPUProcesses = $processInfo | Where-Object { $_.CPU -gt $MaxProcessCPU }
        $highMemoryProcesses = $processInfo | Where-Object { $_.MemoryMB -gt $MaxProcessMemoryMB }

        if ($highCPUProcesses.Count -gt 0) {
            $warns += "Processos com alto uso de CPU"
        }

        if ($highMemoryProcesses.Count -gt 0) {
            $warns += "Processos com alto uso de memória"
        }
    }

    if ($serviceInfo) {
        $stoppedServices = $serviceInfo | Where-Object { $_.Status -ne "Running" }
        if ($stoppedServices.Count -gt 0) {
            $warns += "Serviços críticos parados"
        }
    }

    $Status = if ($crits.Count -gt 0) { "Crítico" }
    elseif ($warns.Count -gt 0) { "Atenção" }
    else { "OK" }

    $report = [pscustomobject]@{
        Hostname       = $computer
        TimestampUtc   = (Get-Date).ToUniversalTime().ToString("o")
        Status         = $Status
        IssuesWarn     = @($warns)
        IssuesCrit     = @($crits)
        CollectionMode = $ModoColeta
        ScriptVersion  = $scriptVersion

        OS             = [pscustomobject]@{
            Caption      = $os.Caption
            Version      = $os.Version
            Build        = $os.BuildNumber
            Architecture = $os.OSArchitecture
            InstallDate  = $os.InstallDate
            LastBoot     = $boot
            Uptime       = $uptime
        }
        Computer       = [pscustomobject]@{
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            Family       = $cs.SystemFamily
            Domain       = $cs.Domain
            Serial       = $bios.SerialNumber
            User         = $cs.UserName
        }
        BIOS           = [pscustomobject]@{
            Vendor      = $bios.Manufacturer
            Version     = $bios.SMBIOSBIOSVersion
            ReleaseDate = $bios.ReleaseDate
        }
        BaseBoard      = [pscustomobject]@{
            Manufacturer = $bb.Manufacturer
            Product      = $bb.Product
            Serial       = $bb.SerialNumber
        }
        CPU            = [pscustomobject]@{
            Name        = $cpuMain.Name
            Cores       = $cpuMain.NumberOfCores
            Logical     = $cpuMain.NumberOfLogicalProcessors
            MaxClockMHz = $cpuMain.MaxClockSpeed
            ProcessorId = $cpuMain.ProcessorId
        }
        GPU            = [pscustomobject]@{
            Name           = if ($gpuMain) { $gpuMain.Name }          else { $null }
            DriverVersion  = if ($gpuMain) { $gpuMain.DriverVersion } else { $null }
            DriverDate     = if ($gpuMain) { $gpuMain.DriverDate }    else { $null }
            VRAM_GB        = if ($gpuMain -and $gpuMain.AdapterRAM) {
                [math]::Round($gpuMain.AdapterRAM / 1GB, 2)
            }
            else { $null }
            Resolution     = $gpuResolutionStr
            RefreshRate    = if ($gpuCurrentHz) { "$gpuCurrentHz`Hz" } else { $null }
            MaxRefreshRate = if ($gpuMaxHz) { "$gpuMaxHz`Hz" } else { $null }
        }
        Monitor        = [pscustomobject]@{
            Count           = ($monitors | Measure-Object).Count
            Monitors        = @($monitors)
            WinFormsScreens = @($screenInfo)
        }
        RAM            = [pscustomobject]@{
            TotalGB     = $totalRAM
            FreeGB      = $freeRAM
            FreePercent = $freeRAMpct
            Modules     = @($ramMods)
        }
        Storage        = [pscustomobject]@{
            Volumes = @($volumes)
            Disks   = @($discos)
        }
        Network        = [pscustomobject]@{
            IPv4     = @($ipv4s)
            MACs     = @($macs)
            Adapters = @($nicDetails)
        }
        Temps          = [pscustomobject]@{
            ACPI_MaxC = $acpiMaxC
            Disk_MaxC = $diskMaxC
            MaxC      = $maxTemp
            LibreHW   = [pscustomobject]@{
                CPU       = [pscustomobject]@{
                    ValueC  = $lhmSummary.CPU
                    Display = (Format-TempDisplay $lhmSummary.CPU)
                }
                GPU       = [pscustomobject]@{
                    ValueC  = $lhmSummary.GPU
                    Display = (Format-TempDisplay $lhmSummary.GPU)
                }
                RAM       = [pscustomobject]@{
                    ValueC  = $lhmSummary.RAM
                    Display = (Format-TempDisplay $lhmSummary.RAM)
                }
                Storage   = [pscustomobject]@{
                    ValueC  = $lhmSummary.Storage
                    Display = (Format-TempDisplay $lhmSummary.Storage)
                }
                Mainboard = [pscustomobject]@{
                    ValueC  = $lhmSummary.Mainboard
                    Display = (Format-TempDisplay $lhmSummary.Mainboard)
                }
                Chipset   = [pscustomobject]@{
                    ValueC  = $lhmSummary.Chipset
                    Display = (Format-TempDisplay $lhmSummary.Chipset)
                }
                Sensors   = @($lhmSummary.Sensors)
            }
        }
        Processes      = @($processInfo)
        Services       = @($serviceInfo)
        Software       = @($softwareInfo)
        EventLogs      = @($eventLogInfo)
        Security       = $securityInfo
    }

    return $report
}

# ----------------- Execução principal -----------------
function Invoke-InventoryRun {
    $runStartTime = Get-Date
    try {
        New-Dir $RepoRoot

        Write-Log "Iniciando inventário de TI - Versão $scriptVersion"
        Write-Log "Computador: $computer"
        Write-Log "Modo de coleta: $ModoColeta"
        Write-Log "Usuário: $env:USERNAME"
        Write-Log "Admin: $(Test-Admin)"

        $report = Get-SystemInventory

        try {
            if ($report -and $report.Temps -and $report.Temps.LibreHW) {
                $lhm = $report.Temps.LibreHW

                if ($lhm.Sensors -and $lhm.Sensors.Count -eq 1) {
                    $src = $lhm.Sensors[0]

                    foreach ($field in 'CPU', 'GPU', 'RAM', 'Storage', 'Mainboard', 'Chipset') {
                        if ($src.PSObject.Properties.Name -contains $field) {
                            $lhm.$field = $src.$field
                        }
                    }

                    if ($src.PSObject.Properties.Name -contains 'Sensors') {
                        $lhm.Sensors = $src.Sensors
                    }
                }
            }
        }
        catch {
            Write-Log "Falha ao normalizar estrutura de temperaturas (LibreHardwareMonitor): $($_.Exception.Message)" "WARNING"
        }

        try {
            if ($report -and $report.Temps) {
                $maxList = @()

                if ($null -ne $report.Temps.ACPI_MaxC) {
                    $maxList += [double]$report.Temps.ACPI_MaxC
                }

                if ($null -ne $report.Temps.Disk_MaxC) {
                    $maxList += [double]$report.Temps.Disk_MaxC
                }

                if ($report.Temps.LibreHW) {
                    $lhm = $report.Temps.LibreHW

                    foreach ($field in 'CPU', 'GPU', 'RAM', 'Storage', 'Mainboard', 'Chipset') {
                        if ($lhm.$field -and $null -ne $lhm.$field.ValueC) {
                            $maxList += [double]$lhm.$field.ValueC
                        }
                    }
                }

                if ($maxList.Count -gt 0) {
                    $report.Temps.MaxC = ($maxList | Measure-Object -Maximum).Maximum
                }
            }
        }
        catch {
            Write-Log "Falha ao recalcular Temps.MaxC: $($_.Exception.Message)" "WARNING"
        }

        if (-not $DisableJSON) {
            $root = $RepoRoot.TrimEnd('\', '/')
            $machinesDir = Join-Path $root "machines"
            $manifestPath = Join-Path $root "manifest.json"
            $lockPath = Join-Path $root ".manifest.lock"

            New-Dir $root
            New-Dir $machinesDir

            $hostJsonPath = Join-Path $machinesDir ("{0}.json" -f $computer)
            $jsonHost = ($report | ConvertTo-Json -Depth 12)
            AtomicWrite-Text -path $hostJsonPath -content $jsonHost

            $lockStream = Acquire-Lock -lockPath $lockPath -tries $LockMaxTries -sleepMs $LockSleepMs
            if ($lockStream) {
                try {
                    $manifest = @()
                    if (Test-Path -LiteralPath $manifestPath) {
                        try {
                            $raw = Get-Content -Raw -Path $manifestPath -Encoding UTF8
                            $trim = $raw.Trim()
                            if ($trim.StartsWith("[")) {
                                $manifest = $raw | ConvertFrom-Json -ErrorAction Stop
                            }
                            elseif ($trim.StartsWith("{")) {
                                $manifest = @($raw | ConvertFrom-Json -ErrorAction Stop)
                            }
                        }
                        catch {
                            $manifest = @()
                        }
                    }
                    if ($manifest -isnot [System.Collections.IList]) { $manifest = @($manifest) }

                    $relPath = "machines/{0}.json" -f $computer
                    $entry = [pscustomobject]@{
                        Hostname       = $computer
                        Json           = $relPath
                        TimestampUtc   = $report.TimestampUtc
                        Status         = $report.Status
                        OS             = $report.OS.Caption
                        CollectionMode = $ModoColeta
                    }

                    $idx = -1
                    for ($i = 0; $i -lt $manifest.Count; $i++) {
                        if ($manifest[$i].Hostname -eq $computer) { $idx = $i; break }
                    }
                    if ($idx -ge 0) { $manifest[$idx] = $entry } else { $manifest += $entry }

                    $manifest = @(
                        $manifest |
                        Sort-Object @{ Expression = { Get-SeverityWeight $_.Status }; Descending = $true }, Hostname
                    )

                    $manifestJson = ConvertTo-JsonForceArray -Collection $manifest -Depth 6
                    AtomicWrite-Text -path $manifestPath -content $manifestJson
                }
                finally {
                    Release-Lock -stream $lockStream -lockPath $lockPath
                }
            }
        }

        $endTime = Get-Date
        $duration = $endTime - $runStartTime
        Write-Log "Inventário concluído com sucesso em $([math]::Round($duration.TotalSeconds, 2)) segundos"

        return $true
    }
    catch {
        Write-Log "Erro fatal no script: $($_.Exception.Message)" "ERROR"
        Write-Log $_.ScriptStackTrace "ERROR"
        return $false
    }
}

if ($IntervaloExecucao -gt 0) {
    while ($true) {
        if (-not (Invoke-InventoryRun)) {
            exit 1
        }
        Write-Log "Aguardando próximo ciclo em $IntervaloExecucao segundos..."
        Start-Sleep -Seconds $IntervaloExecucao
        Write-Log "Reiniciando ciclo de inventário..."
    }
}
else {
    if (-not (Invoke-InventoryRun)) {
        exit 1
    }
}