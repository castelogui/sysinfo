#  GPO-AQS-COMPLETE-SYSINFO.ps1
#  - Coleta inventário local avançado
#  - Suporte a múltiplos modos de coleta e armazenamento
#  - Persistência histórica e alertas avançados
#  Requisitos: Windows PowerShell 5.1

param(
    [string]$RepoRoot = "\\192.168.16.3\brasilsuperatacado\sysinfo",
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

# --- Display Hz/Res por DISPLAYx via User32 EnumDisplaySettings ---
# Observação: no Windows, o número mostrado em Configurações (1/2/3...) NÃO é obrigatoriamente o mesmo do \\.\DISPLAY1/\\.\DISPLAY2.
# O importante aqui é correlacionar cada DISPLAYx com o EDID (serial/modelo) e coletar resolução/Hz atuais de forma confiável.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class DisplayApi {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
  public struct DEVMODE {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
    public string dmDeviceName;
    public short dmSpecVersion;
    public short dmDriverVersion;
    public short dmSize;
    public short dmDriverExtra;
    public int dmFields;
    public int dmPositionX;
    public int dmPositionY;
    public int dmDisplayOrientation;
    public int dmDisplayFixedOutput;
    public short dmColor;
    public short dmDuplex;
    public short dmYResolution;
    public short dmTTOption;
    public short dmCollate;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
    public string dmFormName;
    public short dmLogPixels;
    public int dmBitsPerPel;
    public int dmPelsWidth;
    public int dmPelsHeight;
    public int dmDisplayFlags;
    public int dmDisplayFrequency;
    public int dmICMMethod;
    public int dmICMIntent;
    public int dmMediaType;
    public int dmDitherType;
    public int dmReserved1;
    public int dmReserved2;
    public int dmPanningWidth;
    public int dmPanningHeight;
  }

  [DllImport("user32.dll", CharSet=CharSet.Ansi)]
  public static extern bool EnumDisplaySettings(string lpszDeviceName, int iModeNum, ref DEVMODE lpDevMode);

  public const int ENUM_CURRENT_SETTINGS = -1;
}
"@ -ErrorAction Stop

function Get-DisplayModesPerScreen {
    # Usa WinForms apenas para listar \\.\DISPLAYx existentes no contexto atual
    Add-Type -AssemblyName System.Windows.Forms | Out-Null
    $screens = [System.Windows.Forms.Screen]::AllScreens

    $out = @()

    foreach ($s in $screens) {
        $dev = $s.DeviceName  # \\.\DISPLAY1, \\.\DISPLAY2...

        # Atual
        $cur = New-Object DisplayApi+DEVMODE
        $cur.dmSize = [Runtime.InteropServices.Marshal]::SizeOf([type]([DisplayApi+DEVMODE]))
        $okCur = [DisplayApi]::EnumDisplaySettings($dev, [DisplayApi]::ENUM_CURRENT_SETTINGS, [ref]$cur)

        $curW = if ($okCur) { $cur.dmPelsWidth } else { $null }
        $curH = if ($okCur) { $cur.dmPelsHeight } else { $null }
        $curHz = if ($okCur -and $cur.dmDisplayFrequency -gt 0) { [int]$cur.dmDisplayFrequency } else { $null }

        # Máximo (global e na resolução atual)
        $maxHz = $null
        $maxHzAtCur = $null
        for ($i = 0; ; $i++) {
            $m = New-Object DisplayApi+DEVMODE
            $m.dmSize = [Runtime.InteropServices.Marshal]::SizeOf([type]([DisplayApi+DEVMODE]))
            if (-not [DisplayApi]::EnumDisplaySettings($dev, $i, [ref]$m)) { break }

            $hz = [int]$m.dmDisplayFrequency
            if ($hz -le 0) { continue }

            if (-not $maxHz -or $hz -gt $maxHz) { $maxHz = $hz }

            if ($curW -and $curH -and $m.dmPelsWidth -eq $curW -and $m.dmPelsHeight -eq $curH) {
                if (-not $maxHzAtCur -or $hz -gt $maxHzAtCur) { $maxHzAtCur = $hz }
            }
        }

        $bestMax = if ($maxHzAtCur) { $maxHzAtCur } else { $maxHz }

        $out += [pscustomobject]@{
            DeviceName = $dev
            Primary    = [bool]$s.Primary
            WidthPx    = $curW
            HeightPx   = $curH
            Resolution = if ($curW -and $curH) { "$curW`x$curH" } else { $null }
            CurrentHz  = $curHz
            MaxHz      = $bestMax
        }
    }

    return $out
}

# ----------------- Configuração inicial -----------------
$ErrorActionPreference = "Stop"
$computer = $env:COMPUTERNAME
# Forçar execução completa (opções desativadas)
$ModoColeta = "Completo"

$scriptVersion = "2.5"

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
function Get-GpuVramBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object]$Gpu
    )

    function Convert-RegValueToInt64 {
        param([object]$Value)

        if ($null -eq $Value) { return $null }

        # REG_BINARY -> byte[]
        if ($Value -is [byte[]]) {
            if ($Value.Length -ge 8) {
                return [int64][BitConverter]::ToUInt64($Value, 0)  # 8 bytes (little-endian)
            }
            elseif ($Value.Length -ge 4) {
                return [int64][BitConverter]::ToUInt32($Value, 0)  # 4 bytes
            }
            else {
                return $null
            }
        }

        # Tipos numéricos
        if ($Value -is [int64] -or $Value -is [uint64] -or $Value -is [int32] -or $Value -is [uint32]) {
            return [int64]$Value
        }

        # String numérica (fallback)
        $s = [string]$Value
        [int64]$out = 0
        if ([int64]::TryParse($s, [ref]$out)) { return $out }

        return $null
    }

    if (-not $Gpu) { return $null }

    # Valor atual (pode vir "capado" em ~4GB)
    $adapterRam = $null
    try { $adapterRam = [int64]$Gpu.AdapterRAM } catch { }

    $pnp = $Gpu.PNPDeviceID
    $venDev = $null
    if ($pnp -match 'VEN_[0-9A-Fa-f]{4}&DEV_[0-9A-Fa-f]{4}') {
        $venDev = $matches[0].ToUpperInvariant()
    }

    # 1) Class GUID de Display Adapters
    $classBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    $classKeys = @()
    try { $classKeys = @(Get-ChildItem -Path $classBase -ErrorAction SilentlyContinue) } catch { $classKeys = @() }

    foreach ($k in $classKeys) {
        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p) { continue }

        $isMatch = $false

        if ($venDev -and $p.PSObject.Properties.Name -contains 'MatchingDeviceId' -and $p.MatchingDeviceId) {
            if ($p.MatchingDeviceId.ToUpperInvariant().Contains($venDev)) { $isMatch = $true }
        }

        if (-not $isMatch -and $Gpu.Name -and $p.PSObject.Properties.Name -contains 'DriverDesc' -and $p.DriverDesc) {
            if ($p.DriverDesc -eq $Gpu.Name) { $isMatch = $true }
        }

        if (-not $isMatch) { continue }

        $mem = $null
        if ($p.PSObject.Properties.Name -contains 'HardwareInformation.qwMemorySize') {
            $mem = $p.'HardwareInformation.qwMemorySize'
        }
        elseif ($p.PSObject.Properties.Name -contains 'HardwareInformation.MemorySize') {
            $mem = $p.'HardwareInformation.MemorySize'
        }

        $mem64 = Convert-RegValueToInt64 $mem
        if ($mem64 -ne $null -and $mem64 -gt 0) { return $mem64 }
    }

    # 2) Fallback: Control\Video
    $videoBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Video'
    $videoGuids = @()
    try { $videoGuids = @(Get-ChildItem -Path $videoBase -ErrorAction SilentlyContinue) } catch { $videoGuids = @() }

    foreach ($g in $videoGuids) {
        foreach ($sub in @('0000', '0001')) {
            $kp = Join-Path $g.PSPath $sub
            $p = Get-ItemProperty -Path $kp -ErrorAction SilentlyContinue
            if (-not $p) { continue }

            $isMatch = $false

            if ($Gpu.Name) {
                $adapterStr = $null
                if ($p.PSObject.Properties.Name -contains 'HardwareInformation.AdapterString') {
                    $adapterStr = $p.'HardwareInformation.AdapterString'
                }
                if ($adapterStr -and $adapterStr -like "*$($Gpu.Name)*") { $isMatch = $true }
            }

            if (-not $isMatch -and $venDev -and $p.PSObject.Properties.Name -contains 'MatchingDeviceId' -and $p.MatchingDeviceId) {
                if ($p.MatchingDeviceId.ToUpperInvariant().Contains($venDev)) { $isMatch = $true }
            }

            if (-not $isMatch) { continue }

            $mem = $null
            if ($p.PSObject.Properties.Name -contains 'HardwareInformation.qwMemorySize') {
                $mem = $p.'HardwareInformation.qwMemorySize'
            }
            elseif ($p.PSObject.Properties.Name -contains 'HardwareInformation.MemorySize') {
                $mem = $p.'HardwareInformation.MemorySize'
            }

            $mem64 = Convert-RegValueToInt64 $mem
            if ($mem64 -ne $null -and $mem64 -gt 0) { return $mem64 }
        }
    }

    # Último fallback
    return $adapterRam
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
using System.Collections.Generic;
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

    [Flags]
    public enum DisplayDeviceStateFlags : int
    {
        AttachedToDesktop = 0x1,
        MultiDriver = 0x2,
        PrimaryDevice = 0x4,
        MirroringDriver = 0x8,
        VGACompatible = 0x10,
        Removable = 0x20,
        ModesPruned = 0x8000000,
        Remote = 0x4000000,
        Disconnect = 0x2000000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct DISPLAY_DEVICE
    {
        public int cb;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DeviceName;     // \\.\DISPLAY1

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceString;

        public DisplayDeviceStateFlags StateFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceID;       // Ex: PCI\VEN_...

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string DeviceKey;
    }

    public class DisplayPath
    {
        public string DisplayName;    // \\.\DISPLAY1
        public string DisplayString;
        public string DisplayId;      // PCI\...

        public bool Attached;
        public bool Primary;

        public string MonitorId;      // MONITOR\XXXX\...
        public string MonitorString;

        public int Width;
        public int Height;
        public int RefreshRate;
        public int BitsPerPel;
    }

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool EnumDisplayDevices(string lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

    public static DisplayPath[] GetActiveDisplayPaths()
    {
        var list = new List<DisplayPath>();

        for (uint i = 0; i < 128; i++)
        {
            DISPLAY_DEVICE dd = new DISPLAY_DEVICE();
            dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));

            if (!EnumDisplayDevices(null, i, ref dd, 0))
                break;

            bool attached = (dd.StateFlags & DisplayDeviceStateFlags.AttachedToDesktop) != 0;
            bool mirroring = (dd.StateFlags & DisplayDeviceStateFlags.MirroringDriver) != 0;

            if (!attached || mirroring)
                continue;

            var dm = new DEVMODE();
            dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));

            int width = 0, height = 0, freq = 0, bpp = 0;

            if (EnumDisplaySettings(dd.DeviceName, -1, ref dm))
            {
                width = (int)dm.dmPelsWidth;
                height = (int)dm.dmPelsHeight;
                freq = (int)dm.dmDisplayFrequency;
                bpp = (int)dm.dmBitsPerPel;
            }

            // Monitor ligado ao DISPLAYx (quando disponível)
            DISPLAY_DEVICE md = new DISPLAY_DEVICE();
            md.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));

            string monId = null, monStr = null;
            if (EnumDisplayDevices(dd.DeviceName, 0, ref md, 0))
            {
                monId = md.DeviceID;
                monStr = md.DeviceString;
            }

            list.Add(new DisplayPath
            {
                DisplayName = dd.DeviceName,
                DisplayString = dd.DeviceString,
                DisplayId = dd.DeviceID,
                Attached = attached,
                Primary = (dd.StateFlags & DisplayDeviceStateFlags.PrimaryDevice) != 0,
                MonitorId = monId,
                MonitorString = monStr,
                Width = width,
                Height = height,
                RefreshRate = freq,
                BitsPerPel = bpp
            });
        }

        return list.ToArray();
    }

    public static int GetCurrentRefreshRate(string deviceName)
    {
        DEVMODE dm = new DEVMODE();
        dm.dmSize = (ushort)Marshal.SizeOf(typeof(DEVMODE));
        if (EnumDisplaySettings(deviceName, -1, ref dm))
            return (int)dm.dmDisplayFrequency;
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
                if ((int)dm.dmDisplayFrequency > maxFreq)
                    maxFreq = (int)dm.dmDisplayFrequency;
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
        CPU       = if ($summary.CPU -and $summary.CPU.ValueC -ne $null) { [double]$summary.CPU.ValueC }       else { $null }
        GPU       = if ($summary.GPU -and $summary.GPU.ValueC -ne $null) { [double]$summary.GPU.ValueC }       else { $null }
        RAM       = if ($summary.RAM -and $summary.RAM.ValueC -ne $null) { [double]$summary.RAM.ValueC }       else { $null }
        Storage   = if ($summary.Storage -and $summary.Storage.ValueC -ne $null) { [double]$summary.Storage.ValueC }   else { $null }
        Mainboard = if ($summary.Mainboard -and $summary.Mainboard.ValueC -ne $null) { [double]$summary.Mainboard.ValueC } else { $null }
        Chipset   = if ($summary.Chipset -and $summary.Chipset.ValueC -ne $null) { [double]$summary.Chipset.ValueC }   else { $null }
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
        $gpuVramBytes = $null
        if ($gpuMain) {
            $gpuVramBytes = Get-GpuVramBytes -Gpu $gpuMain
        }

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

                    DisplayName  = $null   # \\.\DISPLAYx (quando correlacionado)
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

    # --- Displays (resolução/Hz reais por \\.\DISPLAYx) + correlação com EDID ---
    $screenInfo = @()
    $displayPaths = @()
    $displayMap = @()

    function Get-PnpCodeFromInstanceName([string]$InstanceName) {
        if ([string]::IsNullOrWhiteSpace($InstanceName)) { return $null }
        $m = [regex]::Match($InstanceName, '(?i)DISPLAY\\([^\\]+)\\')
        if ($m.Success) { return $m.Groups[1].Value.ToUpperInvariant() }
        return $null
    }

    function Get-PnpCodeFromDeviceId([string]$DeviceId) {
        if ([string]::IsNullOrWhiteSpace($DeviceId)) { return $null }

        # Ex.: MONITOR\PHLC326\..., DISPLAY\PHLC326\..., DISPLAY#PHLC326#...
        $m = [regex]::Match($DeviceId, '(?i)(?:MONITOR|DISPLAY)[\\#]+(?<code>[^\\#]+)')
        if ($m.Success) { return $m.Groups['code'].Value.ToUpperInvariant() }

        return $null
    }

    # 1) Preferência: Win32 EnumDisplayDevices/EnumDisplaySettings (sem WinForms/DPI)
    try {
        Ensure-DisplayHelper
        $displayPaths = @([DisplayHelper]::GetActiveDisplayPaths())
    }
    catch {
        $displayPaths = @()
    }

    # 2) Fallback (especialmente em sessão não interativa): registry GraphicsDrivers\Configuration
    #    Observação: esse fallback é bom para RESOLUÇÃO; refresh rate pode não estar disponível.
    function Get-DisplayConfigFromRegistry {
        $out = @()
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration'
        $cfgs = Get-ChildItem -Path $base -ErrorAction SilentlyContinue
        foreach ($cfg in $cfgs) {
            $p00 = Join-Path $cfg.PSPath '00'
            $p0000 = Join-Path $p00 '00'

            $v00 = Get-ItemProperty -Path $p00   -ErrorAction SilentlyContinue
            $v0000 = Get-ItemProperty -Path $p0000 -ErrorAction SilentlyContinue

            $w = $null; $h = $null
            if ($v0000) {
                if ($v0000.PSObject.Properties.Name -contains 'ActiveSize.cx') { $w = $v0000.'ActiveSize.cx' }
                if ($v0000.PSObject.Properties.Name -contains 'ActiveSize.cy') { $h = $v0000.'ActiveSize.cy' }
            }
            if (($null -eq $w -or $null -eq $h) -and $v00) {
                if ($v00.PSObject.Properties.Name -contains 'PrimSurfSize.cx') { $w = $v00.'PrimSurfSize.cx' }
                if ($v00.PSObject.Properties.Name -contains 'PrimSurfSize.cy') { $h = $v00.'PrimSurfSize.cy' }
            }

            if ($w -and $h -and $w -gt 0 -and $h -gt 0) {
                # Heurística: tenta extrair o “código PNP” do nome da chave (ex: ..._DELA0B8_...)
                $pnp = $null
                $m = [regex]::Match($cfg.PSChildName, '_(?<pnp>[A-Z0-9]{3,})_')
                if ($m.Success) { $pnp = $m.Groups['pnp'].Value.ToUpperInvariant() }

                $out += [pscustomobject]@{
                    PnpCode  = $pnp
                    WidthPx  = [int]$w
                    HeightPx = [int]$h
                }
            }
        }
        return $out
    }

    $hasGoodWin32 = $false
    if ($displayPaths -and $displayPaths.Count -gt 0) {
        $hasGoodWin32 = @($displayPaths | Where-Object { $_.Width -gt 0 -and $_.Height -gt 0 }).Count -gt 0
    }

    if (-not $hasGoodWin32) {
        $regCfg = Get-DisplayConfigFromRegistry
        if ($regCfg -and $regCfg.Count -gt 0) {
            # Monta um "displayMap" mínimo (sem DeviceName/Hz), só para preencher resolução corretamente
            foreach ($rc in $regCfg) {
                $displayMap += [pscustomobject]@{
                    DeviceName = $null
                    Primary    = $false
                    WidthPx    = $rc.WidthPx
                    HeightPx   = $rc.HeightPx
                    CurrentHz  = $null
                    MaxHz      = $null
                    PnpCode    = $rc.PnpCode
                    Used       = $false
                }
            }
        }
    }
    else {
        foreach ($d in $displayPaths) {
            $pnp = Get-PnpCodeFromDeviceId $d.MonitorId
            if (-not $pnp) { $pnp = Get-PnpCodeFromDeviceId $d.DisplayId }

            $curHz = $null
            if ([int]$d.RefreshRate -gt 0) { $curHz = [int]$d.RefreshRate }
            elseif ($d.DisplayName) {
                $tmp = 0
                try { $tmp = [DisplayHelper]::GetCurrentRefreshRate($d.DisplayName) } catch { $tmp = 0 }
                if ($tmp -gt 0) { $curHz = [int]$tmp }
            }

            $maxHz = $null
            if ($d.DisplayName -and $d.Width -gt 0 -and $d.Height -gt 0) {
                $tmp2 = 0
                try { $tmp2 = [DisplayHelper]::GetMaxRefreshRate($d.DisplayName, [int]$d.Width, [int]$d.Height) } catch { $tmp2 = 0 }
                if ($tmp2 -gt 0) { $maxHz = [int]$tmp2 }
            }

            $displayMap += [pscustomobject]@{
                DeviceName = $d.DisplayName
                Primary    = [bool]$d.Primary
                WidthPx    = [int]$d.Width
                HeightPx   = [int]$d.Height
                CurrentHz  = $curHz
                MaxHz      = $maxHz
                PnpCode    = $pnp
                Used       = $false
            }
        }
    }

    # Normalização: se existirem entradas reais (DeviceName = \\.\DISPLAYx), ignora as de fallback/ruins
    $named = @($displayMap | Where-Object { $_.DeviceName -and $_.WidthPx -gt 0 -and $_.HeightPx -gt 0 })
    if ($named.Count -gt 0) {
        # Remove duplicidades por DISPLAYx e mantém a melhor (maior resolução / Hz)
        $displayMap = @(
            $named |
            Group-Object DeviceName |
            ForEach-Object {
                $_.Group | Sort-Object `
                @{Expression = { $_.WidthPx * $_.HeightPx }; Descending = $true },
                @{Expression = { if ($_.CurrentHz) { [int]$_.CurrentHz } else { 0 } }; Descending = $true },
                @{Expression = { $_.Primary }; Descending = $true } |
                Select-Object -First 1
            }
        )
    }
    else {
        # Se só sobrou fallback (registry), mantenha apenas entradas com resolução válida, priorizando as maiores
        $displayMap = @(
            $displayMap |
            Where-Object { $_.WidthPx -gt 0 -and $_.HeightPx -gt 0 } |
            Sort-Object @{Expression = { $_.WidthPx * $_.HeightPx }; Descending = $true } |
            Select-Object -First 6
        )
    }

    # Mantém compatibilidade do JSON: "WinFormsScreens" passa a refletir DISPLAYx reais
    if ($displayMap -and $displayMap.Count -gt 0) {
        for ($i = 0; $i -lt $displayMap.Count; $i++) {
            $dm = $displayMap[$i]
            $screenInfo += [pscustomobject]@{
                Index      = $i
                Primary    = $dm.Primary
                WidthPx    = $dm.WidthPx
                HeightPx   = $dm.HeightPx
                DeviceName = $dm.DeviceName
                Resolution = if ($dm.WidthPx -gt 0 -and $dm.HeightPx -gt 0) { '{0}x{1}' -f $dm.WidthPx, $dm.HeightPx } else { $null }
            }
        }
    }

    # Correlaciona EDID (WmiMonitorID.InstanceName) com DISPLAYx (MonitorId/DeviceId) por PnPCode
    if ($monitors.Count -gt 0 -and $displayMap.Count -gt 0) {
        foreach ($mon in $monitors) {
            $monPnp = Get-PnpCodeFromInstanceName $mon.InstanceName

            $match = $null
            $cands = @($displayMap | Where-Object { -not $_.Used -and $_.WidthPx -gt 0 -and $_.HeightPx -gt 0 })

            if ($monPnp) {
                $match = $cands |
                Where-Object { $_.PnpCode -and $_.PnpCode -eq $monPnp } |
                Sort-Object `
                @{Expression = { $_.DeviceName -ne $null }; Descending = $true },
                @{Expression = { $_.CurrentHz -ne $null }; Descending = $true },
                @{Expression = { $_.WidthPx * $_.HeightPx }; Descending = $true },
                @{Expression = { $_.Primary }; Descending = $true },
                DeviceName |
                Select-Object -First 1
            }

            if (-not $match) {
                $match = $cands |
                Sort-Object `
                @{Expression = { $_.DeviceName -ne $null }; Descending = $true },
                @{Expression = { $_.CurrentHz -ne $null }; Descending = $true },
                @{Expression = { $_.WidthPx * $_.HeightPx }; Descending = $true },
                @{Expression = { $_.Primary }; Descending = $true },
                DeviceName |
                Select-Object -First 1
            }

            if ($match) {
                $mon.DisplayName = $match.DeviceName
                $mon.WidthPx = $match.WidthPx
                $mon.HeightPx = $match.HeightPx
                $mon.Resolution = if ($match.WidthPx -and $match.HeightPx) { "{0}x{1}" -f $match.WidthPx, $match.HeightPx } else { $null }
                $mon.CurrentHz = $match.CurrentHz
                $mon.MaxHz = $match.MaxHz
                $mon.Primary = [bool]$match.Primary

                $match.Used = $true
            }
        }

        # Se ninguém ficou como primário, força (para não quebrar dashboards)
        if (-not ($monitors | Where-Object { $_.Primary } | Select-Object -First 1)) {
            $monitors[0].Primary = $true
        }
    }

    # Ajusta GPU.Resolution/Hz para refletir a tela primária real quando disponível
    try {
        $p = $displayMap | Where-Object { $_.Primary -and $_.WidthPx -gt 0 -and $_.HeightPx -gt 0 } | Select-Object -First 1
        if ($p) {
            $gpuResolutionStr = '{0}x{1}' -f $p.WidthPx, $p.HeightPx
            if ($p.CurrentHz) { $gpuCurrentHz = [int]$p.CurrentHz }
            if ($p.MaxHz) { $gpuMaxHz = [int]$p.MaxHz }
        }
    }
    catch { }
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

            VRAM_Bytes     = $gpuVramBytes
            VRAM_GB        = if ($gpuVramBytes -and $gpuVramBytes -gt 0) { [math]::Round($gpuVramBytes / 1GB, 2) } else { $null }

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