<#
 Inventario-GPO-PerHost-Avancado.ps1
 Script refatorado para coleta de inventário local avançado
 Versão: 2.3 (Refatorada)
#>

#region Parâmetros e Configuração
param(
    [string]$RepoRoot = ".",
    [ValidateSet("Completo", "Rapido", "Minimo")]
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
    [string]$SQLitePath = ".\inventory.db",
    [switch]$SkipTemps,
    [switch]$DisableJSON,
    [switch]$EnableRemoteActions,
    [switch]$UsePSSQLite,
    [switch]$UseCSV,
    [switch]$SkipDatabase,
    
    # Lock do manifesto
    [int]$LockMaxTries = 60,
    [int]$LockSleepMs = 500
)

# Configuração inicial
$ErrorActionPreference = "Stop"
$computer = $env:COMPUTERNAME
$startTime = Get-Date
$scriptVersion = "2.3"

# Configurações de log (agora diários)
$logPath = Join-Path $RepoRoot "logs"
$logFile = Join-Path $logPath ("inventory_{0:yyyyMMdd}.log" -f $startTime)
#endregion

#region Funções Auxiliares
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    # Remover caracteres especiais
    $cleanMessage = $Message -replace '[^\x20-\x7E]', ''
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $cleanMessage"
    
    # Garantir que o diretório de log existe
    if (-not (Test-Path $logPath)) {
        New-Item -ItemType Directory -Path $logPath -Force | Out-Null
    }
    
    Add-Content -Path $logFile -Value $logEntry -Encoding UTF8
    
    # Output para console
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        default { Write-Host $logEntry }
    }
}

function Test-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { 
        Write-Log "Erro ao verificar privilegios de administrador: $($_.Exception.Message)" "WARNING"
        return $false 
    }
}

function Ensure-Directory {
    param([string]$Path)
    
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
            Write-Log "Diretorio criado: $Path"
            return $true
        }
        return $true
    }
    catch {
        Write-Log "Erro ao criar diretorio $Path : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-SafeCommand {
    param(
        [scriptblock]$Command,
        [string]$ErrorMessage,
        [object]$DefaultReturn = $null
    )
    
    try {
        return & $Command
    }
    catch {
        Write-Log "$ErrorMessage : $($_.Exception.Message)" "WARNING"
        return $DefaultReturn
    }
}

function Convert-ToGB {
    param($bytes)
    
    if ($bytes -ne $null -and $bytes -is [ValueType] -and $bytes -gt 0) {
        return [math]::Round(([double]$bytes) / 1GB, 2)
    }
    return $null
}

function Calculate-Percentage {
    param($part, $whole)
    
    if (-not $whole -or $whole -eq 0) { return $null }
    return [math]::Round((([double]$part) / ([double]$whole)) * 100, 1)
}

function Format-Uptime {
    param([datetime]$bootTime)
    
    if (-not $bootTime) { return "N/A" }
    $uptime = (Get-Date) - $bootTime
    return "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
}

function Acquire-FileLock {
    param([string]$lockPath, [int]$maxTries, [int]$sleepMs)
    
    for ($i = 0; $i -lt $maxTries; $i++) {
        try {
            return [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch {
            Start-Sleep -Milliseconds $sleepMs
        }
    }
    Write-Log "Nao foi possivel adquirir o lock: $lockPath" "WARNING"
    return $null
}

function Release-FileLock {
    param($lockStream, [string]$lockPath)
    
    try {
        if ($lockStream) {
            $lockStream.Close()
            $lockStream.Dispose()
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

function Write-AtomicText {
    param([string]$path, [string]$content)
    
    $tempPath = "$path.tmp"
    $backupPath = "$path.bak"
    
    try {
        # Escrever no arquivo temporário
        $content | Out-File -FilePath $tempPath -Encoding UTF8 -Force
        
        # Fazer backup do arquivo existente
        if (Test-Path -LiteralPath $path) {
            Move-Item -LiteralPath $path -Destination $backupPath -Force -ErrorAction SilentlyContinue
        }
        
        # Mover temporário para o destino
        Move-Item -LiteralPath $tempPath -Destination $path -Force
        
        # Limpar backup
        if (Test-Path -LiteralPath $backupPath) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
        
        return $true
    }
    catch {
        # Limpar arquivo temporário em caso de erro
        try {
            if (Test-Path -LiteralPath $tempPath) {
                Remove-Item -LiteralPath $tempPath -Force
            }
        }
        catch { }
        
        Write-Log "Erro ao escrever arquivo $path : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-SeverityWeight {
    param([string]$severity)
    
    switch ($severity) {
        "Critico" { return 2 }
        "Atencao" { return 1 }
        default { return 0 }
    }
}

function ConvertTo-JsonArray {
    param([object]$Collection, [int]$Depth = 10)
    
    if ($Collection -is [System.Collections.IList]) {
        return $Collection | ConvertTo-Json -Depth $Depth
    }
    else {
        return @($Collection) | ConvertTo-Json -Depth $Depth
    }
}
#endregion

#region Coleta de Dados
function Get-ProcessInformation {
    Write-Log "Coletando informacoes de processos"
    
    return Invoke-SafeCommand -Command {
        Get-Process | Where-Object { $_.CPU -or $_.WorkingSet } | 
        Sort-Object CPU -Descending | Select-Object -First 15 | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                ID = $_.Id
                CPU = [math]::Round($_.CPU, 2)
                MemoryMB = [math]::Round($_.WorkingSet / 1MB, 2)
                Path = $_.Path
                StartTime = $_.StartTime
            }
        }
    } -ErrorMessage "Falha ao coletar informacoes de processos" -DefaultReturn @()
}

function Get-ServiceInformation {
    Write-Log "Coletando informacoes de servicos"
    
    return Invoke-SafeCommand -Command {
        $criticalServices = @("WinRM", "Spooler", "EventLog", "LanmanServer", "LanmanWorkstation", "DHCP", "DNS")
        Get-Service -Include $criticalServices -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -in $criticalServices } | ForEach-Object {
            $serviceConfig = Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'" -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Status = $_.Status
                StartType = if ($serviceConfig) { $serviceConfig.StartMode } else { "Unknown" }
            }
        }
    } -ErrorMessage "Falha ao coletar informacoes de servicos" -DefaultReturn @()
}

function Get-SoftwareInformation {
    Write-Log "Coletando informacoes de software"
    
    return Invoke-SafeCommand -Command {
        $softwareList = @()
        $uninstallPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $uninstallPaths) {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName -and $_.DisplayName -notmatch '^Update for|^Security Update|^KB\d+' }
            
            foreach ($item in $items) {
                $softwareList += [PSCustomObject]@{
                    Name = $item.DisplayName
                    Version = $item.DisplayVersion
                    Publisher = $item.Publisher
                    InstallDate = $item.InstallDate
                    SizeMB = if ($item.EstimatedSize) { [math]::Round($item.EstimatedSize / 1024, 2) } else { $null }
                }
            }
        }
        
        return $softwareList | Sort-Object SizeMB -Descending | Select-Object -First 20
    } -ErrorMessage "Falha ao coletar informacoes de software" -DefaultReturn @()
}

function Get-EventLogInformation {
    Write-Log "Coletando informacoes de logs de eventos"
    
    return Invoke-SafeCommand -Command {
        $startTime = (Get-Date).AddHours(-24)
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application', 'System'
            Level = 1, 2  # Critical, Error
            StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        if (-not $events) { return @() }
        
        return $events | ForEach-Object {
            [PSCustomObject]@{
                TimeCreated = $_.TimeCreated
                LogName = $_.LogName
                Level = $_.LevelDisplayName
                Provider = $_.ProviderName
                Message = ($_.Message | Out-String).Substring(0, [math]::Min(200, ($_.Message | Out-String).Length))
                EventID = $_.Id
            }
        }
    } -ErrorMessage "Falha ao coletar informacoes de logs de eventos" -DefaultReturn @()
}

function Get-SecurityInformation {
    Write-Log "Coletando informacoes de seguranca"
    
    $securityInfo = @{
        Antivirus = @()
        Firewall = @()
    }
    
    # Informações de antivírus
    $antivirus = Invoke-SafeCommand -Command {
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
    } -ErrorMessage "Falha ao coletar informacoes de antivirus"
    
    if ($antivirus) {
        $securityInfo.Antivirus = $antivirus | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.displayName
                State = if ($_.productState -eq 266240) { "Ativo" } else { "Inativo" }
                Updated = if ($_.productState -eq 266240) { "Atualizado" } else { "Desatualizado" }
            }
        }
    }
    
    # Informações de firewall
    $firewall = Invoke-SafeCommand -Command {
        Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue
    } -ErrorMessage "Falha ao coletar informacoes de firewall"
    
    if ($firewall) {
        $securityInfo.Firewall = $firewall | ForEach-Object {
            [PSCustomObject]@{
                Profile = $_.Name
                Enabled = $_.Enabled
                DefaultIn = $_.DefaultInboundAction
                DefaultOut = $_.DefaultOutboundAction
            }
        }
    }
    
    return $securityInfo
}
#endregion

#region Funções Principais
function Get-SystemInventory {
    Write-Log "Iniciando coleta de inventario (Modo: $ModoColeta)"
    
    # Coleta de dados básicos do sistema
    $computerSystem = Invoke-SafeCommand -Command { Get-CimInstance Win32_ComputerSystem } "Falha ao coletar informacoes do sistema"
    $operatingSystem = Invoke-SafeCommand -Command { Get-CimInstance Win32_OperatingSystem } "Falha ao coletar informacoes do OS"
    $bios = Invoke-SafeCommand -Command { Get-CimInstance Win32_BIOS } "Falha ao coletar informacoes da BIOS"
    $baseBoard = Invoke-SafeCommand -Command { Get-CimInstance Win32_BaseBoard } "Falha ao coletar informacoes da placa-mae"
    $processor = Invoke-SafeCommand -Command { Get-CimInstance Win32_Processor } "Falha ao coletar informacoes da CPU"
    $memory = Invoke-SafeCommand -Command { Get-CimInstance Win32_PhysicalMemory } "Falha ao coletar informacoes da RAM"
    $videoController = Invoke-SafeCommand -Command { Get-CimInstance Win32_VideoController } "Falha ao coletar informacoes da GPU"
    
    # Coleta condicional baseada no modo
    $processInfo = if ($ModoColeta -ne "Minimo") { Get-ProcessInformation } else { @() }
    $serviceInfo = if ($ModoColeta -ne "Minimo") { Get-ServiceInformation } else { @() }
    $softwareInfo = if ($ModoColeta -eq "Completo") { Get-SoftwareInformation } else { @() }
    $eventLogInfo = if ($ModoColeta -eq "Completo") { Get-EventLogInformation } else { @() }
    $securityInfo = if ($ModoColeta -eq "Completo") { Get-SecurityInformation } else { @{} }
    
    # Coleta de informações de armazenamento
    $storageInfo = Get-StorageInformation
    
    # Coleta de informações de rede
    $networkInfo = Get-NetworkInformation
    
    # Coleta de temperaturas (se não desativado)
    $temperatureInfo = if (-not $SkipTemps) { Get-TemperatureInformation } else { @{} }
    
    # Verificação de alertas
    $alertResults = Test-SystemAlerts -OS $operatingSystem -ComputerSystem $computerSystem -StorageInfo $storageInfo -TemperatureInfo $temperatureInfo -ProcessInfo $processInfo -ServiceInfo $serviceInfo
    
    # Montagem do relatório final
    return Build-InventoryReport -ComputerSystem $computerSystem -OS $operatingSystem -BIOS $bios -BaseBoard $baseBoard -Processor $processor -Memory $memory -VideoController $videoController -StorageInfo $storageInfo -NetworkInfo $networkInfo -TemperatureInfo $temperatureInfo -ProcessInfo $processInfo -ServiceInfo $serviceInfo -SoftwareInfo $softwareInfo -EventLogInfo $eventLogInfo -SecurityInfo $securityInfo -AlertResults $alertResults
}

function Get-StorageInformation {
    Write-Log "Coletando informacoes de armazenamento"
    
    $storageInfo = @{
        Volumes = @()
        Disks = @()
    }
    
    # Coleta de volumes
    $volumes = Invoke-SafeCommand -Command { 
        Get-Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter }
    } "Falha ao coletar informacoes de volume"
    
    if (-not $volumes) {
        $volumes = Invoke-SafeCommand -Command {
            Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
                [PSCustomObject]@{
                    DriveLetter = $_.DeviceID.TrimEnd(':')
                    FileSystemLabel = $_.VolumeName
                    FileSystem = $_.FileSystem
                    HealthStatus = $null
                    Size = [double]$_.Size
                    SizeRemaining = [double]$_.FreeSpace
                }
            }
        } "Falha alternativa ao coletar informacoes de volume"
    }
    
    if ($volumes) {
        $storageInfo.Volumes = $volumes | ForEach-Object {
            [PSCustomObject]@{
                DriveLetter = $_.DriveLetter
                Label = $_.FileSystemLabel
                FileSystem = $_.FileSystem
                SizeGB = Convert-ToGB $_.Size
                FreeGB = Convert-ToGB $_.SizeRemaining
                FreePercent = Calculate-Percentage $_.SizeRemaining $_.Size
                Health = $_.HealthStatus
            }
        }
    }
    
    # Coleta de discos físicos
    $physicalDisks = Invoke-SafeCommand -Command { 
        Get-PhysicalDisk -ErrorAction Stop 
    } "Falha ao coletar informacoes de disco fisico"
    
    if (-not $physicalDisks) {
        $physicalDisks = Invoke-SafeCommand -Command {
            Get-CimInstance Win32_DiskDrive | ForEach-Object {
                $diskType = if ($_.InterfaceType -match 'NVME' -or $_.Model -match 'NVME') { 'NVMe' }
                elseif ($_.Model -match 'SSD' -or $_.MediaType -match 'Solid|SSD' -or $_.Model -match 'M\.?2') { 'SSD' }
                else { 'HDD' }
                
                [PSCustomObject]@{
                    Model = $_.Model
                    Serial = $_.SerialNumber
                    Media = $_.MediaType
                    Bus = $_.InterfaceType
                    Type = $diskType
                    SizeGB = Convert-ToGB $_.Size
                    Health = $null
                    OpStatus = $null
                    Spindle = $null
                }
            }
        } "Falha alternativa ao coletar informacoes de disco"
    }
    else {
        $storageInfo.Disks = $physicalDisks | ForEach-Object {
            $diskType = if ($_.BusType -match 'NVMe') { 'NVMe' }
            elseif ($_.MediaType -match 'SSD') { 'SSD' }
            elseif ($_.MediaType -match 'HDD') { 'HDD' }
            elseif ($_.SpindleSpeed -ge 1) { 'HDD' }
            elseif ($_.SpindleSpeed -eq 0) { 'SSD' }
            else { 'Unknown' }
            
            [PSCustomObject]@{
                Model = $_.FriendlyName
                Serial = $_.SerialNumber
                Media = $_.MediaType
                Bus = $_.BusType
                Type = $diskType
                SizeGB = Convert-ToGB $_.Size
                Health = $_.HealthStatus
                OpStatus = ($_.OperationalStatus -join ', ')
                Spindle = $_.SpindleSpeed
            }
        }
    }
    
    return $storageInfo
}

function Get-NetworkInformation {
    Write-Log "Coletando informacoes de rede"
    
    $networkInfo = @{
        IPv4 = @()
        MACs = @()
    }
    
    $ipConfig = Invoke-SafeCommand -Command { 
        Get-NetIPConfiguration -ErrorAction Stop 
    } "Falha ao coletar configuracao de rede"
    
    if ($ipConfig) {
        $networkInfo.IPv4 = $ipConfig | ForEach-Object { 
            $_.IPv4Address.IPAddress 
        } | Where-Object { $_ } | Select-Object -Unique
    }
    
    $networkAdapters = Invoke-SafeCommand -Command {
        Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | 
        Where-Object { $_.NetEnabled -eq $true }
    } "Falha ao coletar adaptadores de rede"
    
    if ($networkAdapters) {
        $networkInfo.MACs = $networkAdapters | ForEach-Object { 
            $_.MACAddress 
        } | Where-Object { $_ } | Select-Object -Unique
    }
    
    return $networkInfo
}

function Get-TemperatureInformation {
    Write-Log "Coletando informacoes de temperatura"
    
    $temps = @{
        ACPI_MaxC = $null
        Disk_MaxC = $null
        MaxC = $null
    }
    
    # Temperaturas ACPI
    $acpiTemps = Invoke-SafeCommand -Command {
        Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' -ErrorAction Stop
    } "Falha ao coletar temperaturas ACPI"
    
    if ($acpiTemps) {
        $maxDeciKelvin = ($acpiTemps | Measure-Object CurrentTemperature -Maximum).Maximum
        if ($maxDeciKelvin) { 
            $temps.ACPI_MaxC = [math]::Round(($maxDeciKelvin / 10) - 273.15, 1) 
        }
    }
    
    # Temperaturas de disco
    $storageTemps = Invoke-SafeCommand -Command {
        try {
            Get-StorageReliabilityCounter -ErrorAction Stop | Where-Object { $_.Temperature -ne $null }
        }
        catch {
            Get-CimInstance -Namespace root\microsoft\windows\storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
            Where-Object { $_.Temperature -ne $null }
        }
    } "Falha ao coletar temperaturas de armazenamento"
    
    if ($storageTemps) {
        $maxDiskTemp = ($storageTemps | Measure-Object Temperature -Maximum).Maximum
        if ($maxDiskTemp) { 
            $temps.Disk_MaxC = [int]$maxDiskTemp 
        }
    }
    
    # Temperatura máxima geral
    $temps.MaxC = ($temps.ACPI_MaxC, $temps.Disk_MaxC | Where-Object { $_ -ne $null } | Measure-Object -Maximum).Maximum
    
    return $temps
}

function Test-SystemAlerts {
    param(
        $OS,
        $ComputerSystem,
        $StorageInfo,
        $TemperatureInfo,
        $ProcessInfo,
        $ServiceInfo
    )
    
    $warnings = @()
    $critical = @()
    
    # Alertas de memória
    $totalRAM = if ($ComputerSystem.TotalPhysicalMemory) { Convert-ToGB $ComputerSystem.TotalPhysicalMemory } else { $null }
    $freeRAM = $null
    $freeRAMPercent = $null
    
    if ($OS -and $OS.FreePhysicalMemory) {
        $freeRAM = [math]::Round(($OS.FreePhysicalMemory * 1KB) / 1GB, 2)
        if ($totalRAM) { 
            $freeRAMPercent = Calculate-Percentage $freeRAM $totalRAM 
        }
    }
    
    if ($totalRAM -and $freeRAM -ne $null) {
        if ($freeRAMPercent -lt 10 -or $freeRAM -lt 1.0) {
            $critical += "RAM livre muito baixa: ${freeRAM}GB (${freeRAMPercent}%)"
        }
        elseif ($freeRAMPercent -lt $MinMemFreePercent -or $freeRAM -lt $MinMemFreeGB) {
            $warnings += "RAM livre baixa: ${freeRAM}GB (${freeRAMPercent}%)"
        }
    }
    
    # Alertas de disco
    $lowDisks = $StorageInfo.Volumes | Where-Object { 
        $_.FreePercent -lt 10 -or $_.FreeGB -lt 10 
    }
    
    $warnDisks = $StorageInfo.Volumes | Where-Object { 
        $_.FreePercent -lt $MinDiskFreePercent -or $_.FreeGB -lt $MinDiskFreeGB 
    }
    
    if ($lowDisks.Count -gt 0) {
        $critical += "Pouco espaco em disco em $($lowDisks.Count) volume(s)"
    }
    elseif ($warnDisks.Count -gt 0) {
        $warnings += "Pouco espaco em disco em $($warnDisks.Count) volume(s)"
    }
    
    # Alertas de temperatura
    if ($TemperatureInfo.MaxC -ne $null) {
        if ($TemperatureInfo.MaxC -ge $HighTempCritC) {
            $critical += "Temperatura elevada: $($TemperatureInfo.MaxC)°C"
        }
        elseif ($TemperatureInfo.MaxC -ge $HighTempWarnC) {
            $warnings += "Temperatura alta: $($TemperatureInfo.MaxC)°C"
        }
    }
    
    # Alertas de processos
    if ($ProcessInfo) {
        $highCPUProcesses = $ProcessInfo | Where-Object { $_.CPU -gt $MaxProcessCPU }
        $highMemoryProcesses = $ProcessInfo | Where-Object { $_.MemoryMB -gt $MaxProcessMemoryMB }
        
        if ($highCPUProcesses.Count -gt 0) {
            $warnings += "Processos com alto uso de CPU: $($highCPUProcesses.Count)"
        }
        
        if ($highMemoryProcesses.Count -gt 0) {
            $warnings += "Processos com alto uso de memoria: $($highMemoryProcesses.Count)"
        }
    }
    
    # Alertas de serviços
    if ($ServiceInfo) {
        $stoppedServices = $ServiceInfo | Where-Object { $_.Status -ne "Running" }
        if ($stoppedServices.Count -gt 0) {
            $warnings += "Servicos criticos parados: $($stoppedServices.Count)"
        }
    }
    
    return @{
        Warnings = $warnings
        Critical = $critical
        Status = if ($critical.Count -gt 0) { "Critico" } elseif ($warnings.Count -gt 0) { "Atencao" } else { "OK" }
    }
}

function Build-InventoryReport {
    param(
        $ComputerSystem,
        $OS,
        $BIOS,
        $BaseBoard,
        $Processor,
        $Memory,
        $VideoController,
        $StorageInfo,
        $NetworkInfo,
        $TemperatureInfo,
        $ProcessInfo,
        $ServiceInfo,
        $SoftwareInfo,
        $EventLogInfo,
        $SecurityInfo,
        $AlertResults
    )
    
    $mainProcessor = if ($Processor) { $Processor | Select-Object -First 1 } else { $null }
    $mainVideoController = if ($VideoController) { $VideoController | Select-Object -First 1 } else { $null }
    
    # Processar módulos de RAM
    $ramModules = @()
    if ($Memory) {
        $ramModules = $Memory | ForEach-Object {
            [PSCustomObject]@{
                Bank = $_.BankLabel
                Slot = $_.DeviceLocator
                Manufacturer = $_.Manufacturer
                PartNumber = $_.PartNumber
                Serial = $_.SerialNumber
                CapacityGB = Convert-ToGB $_.Capacity
                SpeedMHz = $_.Speed
                ConfiguredClockSpeed = $_.ConfiguredClockSpeed
                FormFactor = $_.FormFactor
                SMBIOSMemoryType = $_.SMBIOSMemoryType
            }
        }
    }
    
    # Calcular uso de memória
    $totalRAM = if ($ComputerSystem.TotalPhysicalMemory) { Convert-ToGB $ComputerSystem.TotalPhysicalMemory } else { $null }
    $freeRAM = $null
    $freeRAMPercent = $null
    
    if ($OS -and $OS.FreePhysicalMemory) {
        $freeRAM = [math]::Round(($OS.FreePhysicalMemory * 1KB) / 1GB, 2)
        if ($totalRAM) { 
            $freeRAMPercent = Calculate-Percentage $freeRAM $totalRAM 
        }
    }
    
    return [PSCustomObject]@{
        Hostname = $computer
        TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
        Status = $AlertResults.Status
        IssuesWarn = $AlertResults.Warnings
        IssuesCrit = $AlertResults.Critical
        CollectionMode = $ModoColeta
        ScriptVersion = $scriptVersion
        
        OS = [PSCustomObject]@{
            Caption = $OS.Caption
            Version = $OS.Version
            Build = $OS.BuildNumber
            Architecture = $OS.OSArchitecture
            InstallDate = $OS.InstallDate
            LastBoot = $OS.LastBootUpTime
            Uptime = Format-Uptime $OS.LastBootUpTime
        }
        
        Computer = [PSCustomObject]@{
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            Family = $ComputerSystem.SystemFamily
            Domain = $ComputerSystem.Domain
            Serial = $BIOS.SerialNumber
            User = $ComputerSystem.UserName
        }
        
        BIOS = [PSCustomObject]@{
            Vendor = $BIOS.Manufacturer
            Version = $BIOS.SMBIOSBIOSVersion
            ReleaseDate = $BIOS.ReleaseDate
        }
        
        BaseBoard = [PSCustomObject]@{
            Manufacturer = $BaseBoard.Manufacturer
            Product = $BaseBoard.Product
            Serial = $BaseBoard.SerialNumber
        }
        
        CPU = [PSCustomObject]@{
            Name = $mainProcessor.Name
            Cores = $mainProcessor.NumberOfCores
            Logical = $mainProcessor.NumberOfLogicalProcessors
            MaxClockMHz = $mainProcessor.MaxClockSpeed
            ProcessorId = $mainProcessor.ProcessorId
        }
        
        GPU = [PSCustomObject]@{
            Name = if ($mainVideoController) { $mainVideoController.Name } else { $null }
            DriverVersion = if ($mainVideoController) { $mainVideoController.DriverVersion } else { $null }
            DriverDate = if ($mainVideoController) { $mainVideoController.DriverDate } else { $null }
            VRAM_GB = if ($mainVideoController -and $mainVideoController.AdapterRAM) { 
                Convert-ToGB $mainVideoController.AdapterRAM 
            } else { $null }
            Resolution = if ($mainVideoController) { 
                "${$mainVideoController.CurrentHorizontalResolution}x${$mainVideoController.CurrentVerticalResolution}p" 
            } else { $null }
        }
        
        RAM = [PSCustomObject]@{
            TotalGB = $totalRAM
            FreeGB = $freeRAM
            FreePercent = $freeRAMPercent
            Modules = $ramModules
        }
        
        Storage = [PSCustomObject]@{
            Volumes = $StorageInfo.Volumes
            Disks = $StorageInfo.Disks
        }
        
        Network = [PSCustomObject]@{
            IPv4 = $NetworkInfo.IPv4
            MACs = $NetworkInfo.MACs
        }
        
        Temps = [PSCustomObject]@{
            ACPI_MaxC = $TemperatureInfo.ACPI_MaxC
            Disk_MaxC = $TemperatureInfo.Disk_MaxC
            MaxC = $TemperatureInfo.MaxC
        }
        
        Processes = $ProcessInfo
        Services = $ServiceInfo
        Software = $SoftwareInfo
        EventLogs = $EventLogInfo
        Security = $SecurityInfo
    }
}
#endregion

#region Execução Principal
try {
    # Preparação do ambiente
    Write-Log "Iniciando inventario de TI - Versao $scriptVersion"
    Write-Log "Computador: $computer"
    Write-Log "Modo de coleta: $ModoColeta"
    Write-Log "Usuario: $env:USERNAME"
    Write-Log "Privilegios de administrador: $(Test-Admin)"
    
    # Garantir que os diretórios necessários existem
    Ensure-Directory $RepoRoot | Out-Null
    Ensure-Directory $logPath | Out-Null
    
    # Coletar dados do sistema
    $inventoryReport = Get-SystemInventory
    
    # Persistência dos dados
    if (-not $DisableJSON) {
        Save-InventoryData -Report $inventoryReport
    }
    
    # Log de conclusão
    $endTime = Get-Date
    $duration = $endTime - $startTime
    Write-Log "Inventario concluido com sucesso em $($duration.TotalSeconds) segundos"
    
    # Execução contínua se intervalo configurado
    if ($IntervaloExecucao -gt 0) {
        Write-Log "Aguardando proximo ciclo em $IntervaloExecucao segundos..."
        Start-Sleep -Seconds $IntervaloExecucao
        Write-Log "Reiniciando ciclo de inventario..."
        . $MyInvocation.MyCommand.Path @PSBoundParameters
    }
}
catch {
    Write-Log "Erro fatal no script: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    exit 1
}
#endregion