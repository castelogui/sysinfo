<#
 Inventario-GPO-PerHost-Avancado.ps1
 - Coleta inventário local avançado
 - Suporte a múltiplos modos de coleta e armazenamento
 - Persistência histórica e alertas avançados
 Requisitos: Windows PowerShell 5.1
#>

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

# ----------------- Configuração inicial -----------------
$ErrorActionPreference = "Stop"
$computer = $env:COMPUTERNAME
$startTime = Get-Date
$scriptVersion = "2.2"

# Configurações de log
$logPath = Join-Path $RepoRoot "logs"
$logFile = Join-Path $logPath ("inventory_{0}_{1:yyyyMMdd_HHmmss}.log" -f $computer, $startTime)

# ----------------- Helpers melhorados -----------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    if ($Level -eq "ERROR") { Write-Error $Message }
    elseif ($Level -eq "WARNING") { Write-Warning $Message }
    else { Write-Host $logEntry }
}

function Test-Admin {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
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

function Try-Get([scriptblock]$Block, [string]$ErrorMessage) {
    try {
        $old = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $result = & $Block
        $ErrorActionPreference = $old
        return $result
    }
    catch {
        Write-Log "$ErrorMessage : $($_.Exception.Message)" "WARNING"
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
            return [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
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

# ----------------- Funções de Banco de Dados (Múltiplos Métodos) -----------------
function Initialize-Database {
    param([string]$DbPath)
    
    # Verificar se devemos pular banco de dados
    if ($SkipDatabase) {
        Write-Log "Armazenamento em banco desabilitado via parâmetro -SkipDatabase" "INFO"
        return $false
    }
    
    # Ordem de tentativa baseada nos parâmetros
    $methods = @()
    
    if ($UsePSSQLite) {
        $methods += @{Name = "PSSQLiteModule"; Action = { Initialize-PSSQLite -DbPath $DbPath } }
    }
    elseif ($UseCSV) {
        $methods += @{Name = "CSVStorage"; Action = { Initialize-CSVStorage -DbPath $DbPath } }
    }
    else {
        # Ordem padrão de tentativa
        $methods = @(
            @{Name = "SQLiteModule"; Action = { Initialize-SQLiteModule -DbPath $DbPath } },
            @{Name = "PSSQLiteModule"; Action = { Initialize-PSSQLite -DbPath $DbPath } },
            @{Name = "SQLiteRaw"; Action = { Initialize-SQLiteRaw -DbPath $DbPath } },
            @{Name = "CSVStorage"; Action = { Initialize-CSVStorage -DbPath $DbPath } }
        )
    }
    
    foreach ($method in $methods) {
        try {
            Write-Log "Tentando método: $($method.Name)" "INFO"
            $result = & $method.Action
            if ($result) {
                Write-Log "Banco inicializado com sucesso usando método: $($method.Name)" "INFO"
                return $true
            }
        }
        catch {
            Write-Log "Método $($method.Name) falhou: $($_.Exception.Message)" "WARNING"
        }
    }
    
    Write-Log "Todos os métodos de banco de dados falharam. Funcionalidade limitada." "WARNING"
    return $false
}

function Initialize-SQLiteModule {
    param([string]$DbPath)
    
    try {
        Import-Module SQLite -ErrorAction Stop 2>$null
        Write-Log "Módulo SQLite carregado com sucesso" "INFO"
        
        # Criar conexão e tabelas
        $conn = New-Object System.Data.SQLite.SQLiteConnection
        $conn.ConnectionString = "Data Source=$DbPath"
        $conn.Open()
        
        $command = $conn.CreateCommand()
        $command.CommandText = @"
CREATE TABLE IF NOT EXISTS machine_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    data_json TEXT NOT NULL,
    status TEXT NOT NULL,
    os_name TEXT,
    collection_mode TEXT
);
"@
        $command.ExecuteNonQuery()
        $conn.Close()
        
        return $true
    }
    catch {
        Write-Log "Método SQLiteModule falhou: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Initialize-PSSQLite {
    param([string]$DbPath)
    
    try {
        # Tentar carregar módulo PSSQLite
        $module = Get-Module -Name PSSQLite -ListAvailable -ErrorAction SilentlyContinue
        if (-not $module) {
            Write-Log "Módulo PSSQLite não encontrado" "WARNING"
            return $false
        }
        
        Import-Module PSSQLite -ErrorAction Stop 2>$null
        Write-Log "Módulo PSSQLite carregado com sucesso" "INFO"
        
        # Criar conexão usando PSSQLite
        $conn = New-Object System.Data.SQLite.SQLiteConnection
        $conn.ConnectionString = "Data Source=$DbPath"
        $conn.Open()
        
        $command = $conn.CreateCommand()
        $command.CommandText = @"
CREATE TABLE IF NOT EXISTS machine_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    data_json TEXT NOT NULL,
    status TEXT NOT NULL,
    os_name TEXT,
    collection_mode TEXT
);
"@
        $command.ExecuteNonQuery()
        $conn.Close()
        
        return $true
    }
    catch {
        Write-Log "Método PSSQLite falhou: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Initialize-CSVStorage {
    param([string]$DbPath)
    
    try {
        $csvDir = "$RepoRoot\csv_data"
        New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
        
        # Criar arquivo CSV de metadados
        $csvFile = "$csvDir\database_info.csv"
        if (-not (Test-Path $csvFile)) {
            "hostname,timestamp,status,os_name,collection_mode,json_file" | Out-File -FilePath $csvFile -Encoding UTF8
        }
        
        Write-Log "Armazenamento CSV inicializado: $csvDir" "INFO"
        return $true
    }
    catch {
        Write-Log "Método CSV falhou: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Initialize-SQLiteRaw {
    param([string]$DbPath)
    
    try {
        # Tentar carregar DLL manualmente
        $dllPaths = @(
            ".\libs\System.Data.SQLite.dll",
            ".\System.Data.SQLite.dll",
            "$RepoRoot\libs\System.Data.SQLite.dll",
            "$RepoRoot\System.Data.SQLite.dll"
        )
        
        foreach ($dllPath in $dllPaths) {
            if (Test-Path $dllPath) {
                try {
                    Add-Type -Path $dllPath -ErrorAction Stop
                    Write-Log "DLL SQLite carregada: $dllPath" "INFO"
                    
                    # Criar conexão
                    $conn = New-Object System.Data.SQLite.SQLiteConnection
                    $conn.ConnectionString = "Data Source=$DbPath"
                    $conn.Open()
                    
                    $command = $conn.CreateCommand()
                    $command.CommandText = @"
CREATE TABLE IF NOT EXISTS machine_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    data_json TEXT NOT NULL,
    status TEXT NOT NULL,
    os_name TEXT,
    collection_mode TEXT
);
"@
                    $command.ExecuteNonQuery()
                    $conn.Close()
                    
                    return $true
                }
                catch {
                    Write-Log "Erro ao carregar DLL $dllPath : $($_.Exception.Message)" "WARNING"
                }
            }
        }
        
        Write-Log "Nenhuma DLL SQLite encontrada ou carregável" "WARNING"
        return $false
    }
    catch {
        Write-Log "Método SQLiteRaw falhou: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Save-ToDatabase {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [datetime]$Timestamp,
        [string]$JsonData,
        [string]$Status,
        [string]$OSName,
        [string]$CollectionMode
    )
    
    # Múltiplas tentativas de salvamento
    $methods = @()
    
    if ($UseCSV) {
        $methods += @{Name = "CSV"; Action = { Save-ToCSV @args } }
    }
    else {
        $methods = @(
            @{Name = "SQLiteModule"; Action = { Save-ToSQLiteModule @args } },
            @{Name = "PSSQLite"; Action = { Save-ToPSSQLite @args } },
            @{Name = "SQLiteRaw"; Action = { Save-ToSQLiteRaw @args } },
            @{Name = "CSV"; Action = { Save-ToCSV @args } }
        )
    }
    
    foreach ($method in $methods) {
        try {
            $result = & $method.Action $DbPath $Hostname $Timestamp $JsonData $Status $OSName $CollectionMode
            if ($result) {
                Write-Log "Dados salvos com sucesso usando método: $($method.Name)" "INFO"
                return $true
            }
        }
        catch {
            Write-Log "Método $($method.Name) falhou no salvamento: $($_.Exception.Message)" "WARNING"
        }
    }
    
    return $false
}

function Save-ToSQLiteModule {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [datetime]$Timestamp,
        [string]$JsonData,
        [string]$Status,
        [string]$OSName,
        [string]$CollectionMode
    )
    
    try {
        Import-Module SQLite -ErrorAction Stop 2>$null
        
        $conn = New-Object System.Data.SQLite.SQLiteConnection
        $conn.ConnectionString = "Data Source=$DbPath"
        $conn.Open()
        
        $command = $conn.CreateCommand()
        $command.CommandText = "INSERT INTO machine_inventory (hostname, timestamp, data_json, status, os_name, collection_mode) VALUES (@hostname, @timestamp, @data_json, @status, @os_name, @collection_mode)"
        
        $command.Parameters.AddWithValue("@hostname", $Hostname) | Out-Null
        $command.Parameters.AddWithValue("@timestamp", $Timestamp.ToString("yyyy-MM-dd HH:mm:ss")) | Out-Null
        $command.Parameters.AddWithValue("@data_json", $JsonData) | Out-Null
        $command.Parameters.AddWithValue("@status", $Status) | Out-Null
        $command.Parameters.AddWithValue("@os_name", $OSName) | Out-Null
        $command.Parameters.AddWithValue("@collection_mode", $CollectionMode) | Out-Null
        
        $command.ExecuteNonQuery() | Out-Null
        $conn.Close()
        
        return $true
    }
    catch {
        Write-Log "Erro ao salvar no SQLiteModule: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Save-ToPSSQLite {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [datetime]$Timestamp,
        [string]$JsonData,
        [string]$Status,
        [string]$OSName,
        [string]$CollectionMode
    )
    
    try {
        Import-Module PSSQLite -ErrorAction Stop 2>$null
        
        $conn = New-Object System.Data.SQLite.SQLiteConnection
        $conn.ConnectionString = "Data Source=$DbPath"
        $conn.Open()
        
        $command = $conn.CreateCommand()
        $command.CommandText = "INSERT INTO machine_inventory (hostname, timestamp, data_json, status, os_name, collection_mode) VALUES (@hostname, @timestamp, @data_json, @status, @os_name, @collection_mode)"
        
        $command.Parameters.AddWithValue("@hostname", $Hostname) | Out-Null
        $command.Parameters.AddWithValue("@timestamp", $Timestamp.ToString("yyyy-MM-dd HH:mm:ss")) | Out-Null
        $command.Parameters.AddWithValue("@data_json", $JsonData) | Out-Null
        $command.Parameters.AddWithValue("@status", $Status) | Out-Null
        $command.Parameters.AddWithValue("@os_name", $OSName) | Out-Null
        $command.Parameters.AddWithValue("@collection_mode", $CollectionMode) | Out-Null
        
        $command.ExecuteNonQuery() | Out-Null
        $conn.Close()
        
        return $true
    }
    catch {
        Write-Log "Erro ao salvar no PSSQLite: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Save-ToSQLiteRaw {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [datetime]$Timestamp,
        [string]$JsonData,
        [string]$Status,
        [string]$OSName,
        [string]$CollectionMode
    )
    
    try {
        # Tentar carregar DLL manualmente
        $dllPaths = @(
            ".\libs\System.Data.SQLite.dll",
            ".\System.Data.SQLite.dll",
            "$RepoRoot\libs\System.Data.SQLite.dll"
        )
        
        foreach ($dllPath in $dllPaths) {
            if (Test-Path $dllPath) {
                try {
                    Add-Type -Path $dllPath -ErrorAction Stop
                    
                    $conn = New-Object System.Data.SQLite.SQLiteConnection
                    $conn.ConnectionString = "Data Source=$DbPath"
                    $conn.Open()
                    
                    $command = $conn.CreateCommand()
                    $command.CommandText = "INSERT INTO machine_inventory (hostname, timestamp, data_json, status, os_name, collection_mode) VALUES (@hostname, @timestamp, @data_json, @status, @os_name, @collection_mode)"
                    
                    $command.Parameters.AddWithValue("@hostname", $Hostname) | Out-Null
                    $command.Parameters.AddWithValue("@timestamp", $Timestamp.ToString("yyyy-MM-dd HH:mm:ss")) | Out-Null
                    $command.Parameters.AddWithValue("@data_json", $JsonData) | Out-Null
                    $command.Parameters.AddWithValue("@status", $Status) | Out-Null
                    $command.Parameters.AddWithValue("@os_name", $OSName) | Out-Null
                    $command.Parameters.AddWithValue("@collection_mode", $CollectionMode) | Out-Null
                    
                    $command.ExecuteNonQuery() | Out-Null
                    $conn.Close()
                    
                    return $true
                }
                catch {
                    Write-Log "Erro ao usar DLL $dllPath : $($_.Exception.Message)" "WARNING"
                }
            }
        }
        
        return $false
    }
    catch {
        Write-Log "Erro ao salvar no SQLiteRaw: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Save-ToCSV {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [datetime]$Timestamp,
        [string]$JsonData,
        [string]$Status,
        [string]$OSName,
        [string]$CollectionMode
    )
    
    try {
        $csvDir = "$RepoRoot\csv_data"
        $csvFile = "$csvDir\database_info.csv"
        $jsonFile = "$csvDir\$Hostname-$(Get-Date $Timestamp -Format 'yyyyMMdd_HHmmss').json"
        
        # Salvar JSON separado
        $JsonData | Out-File -FilePath $jsonFile -Encoding UTF8
        
        # Adicionar entrada CSV
        $csvEntry = "$Hostname,$($Timestamp.ToString('yyyy-MM-dd HH:mm:ss')),$Status,$OSName,$CollectionMode,$(Split-Path $jsonFile -Leaf)"
        Add-Content -Path $csvFile -Value $csvEntry -Encoding UTF8
        
        Write-Log "Dados salvos em CSV: $csvFile" "INFO"
        return $true
    }
    catch {
        Write-Log "Erro ao salvar em CSV: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

function Save-Alert {
    param(
        [string]$DbPath,
        [string]$Hostname,
        [string]$AlertType,
        [string]$AlertMessage,
        [string]$AlertSeverity
    )
    
    try {
        # Para simplificar, vamos salvar alertas em arquivo CSV também
        $alertDir = "$RepoRoot\alerts"
        $alertFile = "$alertDir\alerts.csv"
        
        New-Dir $alertDir
        
        if (-not (Test-Path $alertFile)) {
            "timestamp,hostname,alert_type,alert_message,alert_severity" | Out-File -FilePath $alertFile -Encoding UTF8
        }
        
        $alertEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Hostname,$AlertType,$AlertMessage,$AlertSeverity"
        Add-Content -Path $alertFile -Value $alertEntry -Encoding UTF8
        
        Write-Log "Alerta salvo: $AlertType - $AlertSeverity" "INFO"
        return $true
    }
    catch {
        Write-Log "Erro ao salvar alerta: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# ----------------- Coleta de Dados Avançada -----------------
function Get-ProcessInfo {
    Write-Log "Coletando informações de processos"
    
    try {
        $processes = Get-Process | Where-Object { $_.CPU -or $_.WorkingSet } | Sort-Object CPU -Descending | Select-Object -First 15
        
        $processInfo = @()
        foreach ($proc in $processes) {
            $processInfo += [pscustomobject]@{
                Name      = $proc.Name
                ID        = $proc.Id
                CPU       = [math]::Round($proc.CPU, 2)
                MemoryMB  = [math]::Round($proc.WorkingSet / 1MB, 2)
                Path      = $proc.Path
                StartTime = $proc.StartTime
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
        $services = Get-Service -Include $criticalServices -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $criticalServices }
        
        $serviceInfo = @()
        foreach ($svc in $services) {
            $serviceInfo += [pscustomobject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                Status      = $svc.Status
                StartType   = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).StartMode
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
        
        # Software instalado via Uninstall registry keys
        $uninstallPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $uninstallPaths) {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -and $_.EstimatedSize -and $_.EstimatedSize -gt 50
            }
            
            foreach ($item in $items) {
                $software += [pscustomobject]@{
                    Name        = $item.DisplayName
                    Version     = $item.DisplayVersion
                    Publisher   = $item.Publisher
                    InstallDate = $item.InstallDate
                    SizeMB      = [math]::Round($item.EstimatedSize / 1024, 2)
                }
            }
        }
        
        return $software | Sort-Object SizeMB -Descending | Select-Object -First 20
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
        
        # Eventos críticos e de erro dos últimos 24 horas
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application', 'System'
            Level     = 1, 2  # 1=Critical, 2=Error
            StartTime = $startTime
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        if ($events) {
            foreach ($event in $events) {
                $eventLogs += [pscustomobject]@{
                    TimeCreated = $event.TimeCreated
                    LogName     = $event.LogName
                    Level       = $event.LevelDisplayName
                    Provider    = $event.ProviderName
                    Message     = ($event.Message | Out-String).Substring(0, [math]::Min(200, ($event.Message | Out-String).Length))
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
        
        # Informações do antivírus via WMI
        $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue
        if ($antivirus) {
            foreach ($av in $antivirus) {
                $securityInfo.Antivirus += [pscustomobject]@{
                    Name    = $av.displayName
                    State   = if ($av.productState -eq 266240) { "Ativo" } else { "Inativo" }
                    Updated = if ($av.productState -eq 266240) { "Atualizado" } else { "Desatualizado" }
                }
            }
        }
        
        # Status do firewall
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
    
    # Dados básicos (sempre coletados)
    $cs = Try-Get { Get-CimInstance Win32_ComputerSystem } "Falha ao coletar informações do sistema"
    $os = Try-Get { Get-CimInstance Win32_OperatingSystem } "Falha ao coletar informações do OS"
    $bios = Try-Get { Get-CimInstance Win32_BIOS } "Falha ao coletar informações da BIOS"
    $bb = Try-Get { Get-CimInstance Win32_BaseBoard } "Falha ao coletar informações da placa-mãe"
    $cpu = Try-Get { Get-CimInstance Win32_Processor } "Falha ao coletar informações da CPU"
    $ram = Try-Get { Get-CimInstance Win32_PhysicalMemory } "Falha ao coletar informações da RAM"
    $gpu = Try-Get { Get-CimInstance Win32_VideoController } "Falha ao coletar informações da GPU"
    
    # Coleta condicional baseada no modo
    $processInfo = if ($ModoColeta -ne "Minimo") { Get-ProcessInfo } else { @() }
    $serviceInfo = if ($ModoColeta -ne "Minimo") { Get-ServiceInfo } else { @() }
    $softwareInfo = if ($ModoColeta -eq "Completo") { Get-SoftwareInfo } else { @() }
    $eventLogInfo = if ($ModoColeta -eq "Completo") { Get-EventLogInfo } else { @() }
    $securityInfo = if ($ModoColeta -eq "Completo") { Get-SecurityInfo } else { @{} }
    
    # Dados de storage (sempre coletados)
    $vol = Try-Get { Get-Volume -ErrorAction Stop } "Falha ao coletar informações de volume"
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
    
    $pd = $null
    try { $pd = Get-PhysicalDisk -ErrorAction Stop } catch {}
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
            $meddd = [string]$_.MediaType
            $type = if ($bus -match 'NVME' -or $model -match 'NVME') { 'NVMe' }
            elseif ($model -match 'SSD' -or $meddd -match 'Solid|SSD' -or $model -match 'M\.?2') { 'SSD' }
            else { $null }
            [pscustomobject]@{
                Model    = $model
                Serial   = $_.SerialNumber
                Media    = if ($meddd) { $meddd } else { $null }
                Bus      = $bus
                Type     = $type
                SizeGB   = [math]::Round($_.Size / 1GB, 2)
                Health   = $null
                OpStatus = $null
                Spindle  = $null
            }
        }
    }
    
    # Consolidação de Volumes por Disco
    $volDiskMap = @{}
    try {
        $partitions = Get-CimInstance Win32_DiskPartition
        $logicalDisks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        $mappings = Get-CimInstance Win32_LogicalDiskToPartition
        
        foreach ($map in $mappings) {
            $part = ($partitions | Where-Object { $_.DeviceID -eq $map.Antecedent.DeviceID })
            $ld = ($logicalDisks | Where-Object { $_.DeviceID -eq $map.Dependent.DeviceID })
            if ($part -and $ld) {
                $diskIndex = $part.DiskIndex
                if (-not $volDiskMap.ContainsKey($diskIndex)) {
                    $volDiskMap[$diskIndex] = @()
                }
                $volDiskMap[$diskIndex] += $ld
            }
        }
    }
    catch {
        $volDiskMap[-1] = $vol
    }
    
    $volumes = @()
    foreach ($diskIndex in $volDiskMap.Keys) {
        $vols = $volDiskMap[$diskIndex]
        if ($vols) {
            $largest = $vols | Sort-Object { [double]$_.Size } -Descending | Select-Object -First 1
            $sz = [double]$largest.Size
            $rem = [double]$largest.FreeSpace
            $volumes += [pscustomobject]@{
                DriveLetter = $largest.DeviceID.TrimEnd(':')
                Label       = $largest.VolumeName
                FileSystem  = $largest.FileSystem
                SizeGB      = [math]::Round($sz / 1GB, 2)
                FreeGB      = [math]::Round($rem / 1GB, 2)
                FreePercent = if ($sz) { [math]::Round(($rem / $sz) * 100, 1) } else { $null }
                Health      = $null
            }
        }
    }
    
    # RAM módulos
    $ramMods = @()
    if ($ram) {
        $ramMods = @($ram | ForEach-Object {
                [pscustomobject]@{
                    Bank       = $_.BankLabel
                    Slot       = $_.DeviceLocator
                    Manuf      = $_.Manufacturer
                    Part       = $_.PartNumber
                    Serial     = $_.SerialNumber
                    CapacityGB = [math]::Round($_.Capacity / 1GB, 2)
                    SpeedMHz   = $_.Speed
                    ConfClk    = $_.ConfiguredClockSpeed
                    Form       = $_.FormFactor
                    SMBIOSType = $_.SMBIOSMemoryType
                }
            })
    }
    
    # Rede
    $netCfg = Try-Get { Get-NetIPConfiguration } "Falha ao coletar configuração de rede"
    $ipv4s = @(); $macs = @()
    try { $ipv4s = @($netCfg | ForEach-Object { $_.IPv4Address.IPAddress } | Where-Object { $_ } | Select-Object -Unique) } catch {}
    try { $macs = @((Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" | Where-Object { $_.NetEnabled -eq $true }).MACAddress | Where-Object { $_ } | Select-Object -Unique) } catch {}
    
    # Uptime/CPU
    $boot = $os.LastBootUpTime; $uptime = Get-UptimeString $boot
    $cpuMain = $cpu | Select-Object -First 1
    
    # Temperaturas
    $acpiMaxC = $null; $diskMaxC = $null
    if (-not $SkipTemps) {
        $acpiTemps = Try-Get { Get-CimInstance -Namespace 'root/wmi' -ClassName 'MSAcpi_ThermalZoneTemperature' } "Falha ao coletar temperaturas ACPI"
        if ($acpiTemps) {
            $maxDeciK = ($acpiTemps | Measure-Object CurrentTemperature -Maximum).Maximum
            if ($maxDeciK) { $acpiMaxC = [math]::Round(($maxDeciK / 10) - 273.15, 1) }
        }
        $storRel = Try-Get { 
            try {
                Get-StorageReliabilityCounter -ErrorAction Stop | Where-Object { $_.Temperature -ne $null }
            }
            catch {
                # Fallback para WMI
                Get-CimInstance -Namespace root\microsoft\windows\storage -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue |
                Where-Object { $_.Temperature -ne $null }
            }
        } "Falha ao coletar contadores de armazenamento"
        if ($storRel) {
            $t = ($storRel | Where-Object Temperature -ne $null | Measure-Object Temperature -Maximum).Maximum
            if ($t -ne $null) { $diskMaxC = [int]$t }
        }
    }
    $maxTemp = ($acpiMaxC, $diskMaxC | Where-Object { $_ -ne $null } | Measure-Object -Maximum).Maximum
    
    # Verificação de alertas
    $warns = @(); $crits = @()
    $totalRAM = if ($cs.TotalPhysicalMemory) { To-GB $cs.TotalPhysicalMemory } else { $null }
    $freeRAM = $null; $freeRAMpct = $null
    if ($os -and $os.FreePhysicalMemory) {
        $freeRAM = [math]::Round((($os.FreePhysicalMemory * 1KB) / 1GB), 2)
        if ($totalRAM) { $freeRAMpct = Percent $freeRAM $totalRAM }
    }
    
    # Alertas de RAM
    if ($totalRAM -and $freeRAM -ne $null) {
        if ($freeRAMpct -lt 10 -or $freeRAM -lt 1.0) {
            $crits += "RAM livre muito baixa"
            Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "RAM" -AlertMessage "RAM livre muito baixa: $freeRAM GB ($freeRAMpct%)" -AlertSeverity "Crítico"
        }
        elseif ($freeRAMpct -lt $MinMemFreePercent -or $freeRAM -lt $MinMemFreeGB) {
            $warns += "RAM livre baixa"
            Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "RAM" -AlertMessage "RAM livre baixa: $freeRAM GB ($freeRAMpct%)" -AlertSeverity "Atenção"
        }
    }
    
    # Alertas de disco
    $lowDisks = $volumes | Where-Object { $_.FreePercent -lt 10 -or $_.FreeGB -lt 10 }
    $warnDisks = $volumes | Where-Object { $_.FreePercent -lt $MinDiskFreePercent -or $_.FreeGB -lt $MinDiskFreeGB }
    if ($lowDisks.Count -gt 0) {
        $crits += "Pouco espaço em disco"
        Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Disco" -AlertMessage "Pouco espaço em disco em $($lowDisks.Count) volume(s)" -AlertSeverity "Crítico"
    }
    elseif ($warnDisks.Count -gt 0) {
        $warns += "Pouco espaço em disco"
        Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Disco" -AlertMessage "Pouco espaço em disco em $($warnDisks.Count) volume(s)" -AlertSeverity "Atenção"
    }
    
    # Alertas de temperatura
    if ($maxTemp -ne $null) {
        if ($maxTemp -ge $HighTempCritC) {
            $crits += "Temperatura elevada"
            Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Temperatura" -AlertMessage "Temperatura elevada: $maxTemp°C" -AlertSeverity "Crítico"
        }
        elseif ($maxTemp -ge $HighTempWarnC) {
            $warns += "Temperatura alta"
            Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Temperatura" -AlertMessage "Temperatura alta: $maxTemp°C" -AlertSeverity "Atenção"
        }
    }
    
    # Alertas de processos
    if ($processInfo) {
        $highCPUProcesses = $processInfo | Where-Object { $_.CPU -gt $MaxProcessCPU }
        $highMemoryProcesses = $processInfo | Where-Object { $_.MemoryMB -gt $MaxProcessMemoryMB }
        
        if ($highCPUProcesses.Count -gt 0) {
            $warns += "Processos com alto uso de CPU"
            foreach ($proc in $highCPUProcesses) {
                Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Processo" -AlertMessage "Processo $($proc.Name) usando $($proc.CPU)% de CPU" -AlertSeverity "Atenção"
            }
        }
        
        if ($highMemoryProcesses.Count -gt 0) {
            $warns += "Processos com alto uso de memória"
            foreach ($proc in $highMemoryProcesses) {
                Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Processo" -AlertMessage "Processo $($proc.Name) usando $($proc.MemoryMB) MB de memória" -AlertSeverity "Atenção"
            }
        }
    }
    
    # Alertas de serviços
    if ($serviceInfo) {
        $stoppedServices = $serviceInfo | Where-Object { $_.Status -ne "Running" }
        if ($stoppedServices.Count -gt 0) {
            $warns += "Serviços críticos parados"
            foreach ($svc in $stoppedServices) {
                Save-Alert -DbPath $SQLitePath -Hostname $computer -AlertType "Serviço" -AlertMessage "Serviço $($svc.Name) parado" -AlertSeverity "Atenção"
            }
        }
    }
    
    $Status = if ($crits.Count -gt 0) { "Crítico" } elseif ($warns.Count -gt 0) { "Atenção" } else { "OK" }
    
    # GPU
    $gpuArr = @()
    if ($gpu) {
        $gpuArr = @($gpu | ForEach-Object {
                [pscustomobject]@{
                    Name       = $_.Name
                    DriverVer  = $_.DriverVersion
                    DriverDate = $_.DriverDate
                    VRAM_GB    = if ($_.AdapterRAM) { [math]::Round($_.AdapterRAM / 1GB, 2) } else { $null }
                }
            })
    }
    
    # Montagem do objeto de relatório
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
            Serial       = $bios.SerialNumber
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
        GPU            = @($gpuArr)
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
            IPv4 = @($ipv4s)
            MACs = @($macs)
        }
        Temps          = [pscustomobject]@{
            ACPI_MaxC = $acpiMaxC
            Disk_MaxC = $diskMaxC
            MaxC      = $maxTemp
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
try {
    # Preparação do ambiente
    New-Dir $RepoRoot
    New-Dir $logPath
    
    Write-Log "Iniciando inventário de TI - Versão $scriptVersion"
    Write-Log "Computador: $computer"
    Write-Log "Modo de coleta: $ModoColeta"
    Write-Log "Usuário: $env:USERNAME"
    Write-Log "Admin: $(Test-Admin)"
    
    # Inicializar banco de dados (múltiplos métodos)
    $dbInitialized = Initialize-Database -DbPath $SQLitePath
    
    # Coletar dados do sistema
    $report = Get-SystemInventory
    
    # Persistência por host + manifesto (se não desabilitado)
    if (-not $DisableJSON) {
        $root = $RepoRoot.TrimEnd('\', '/')
        $machinesDir = Join-Path $root "machines"
        $manifestPath = Join-Path $root "manifest.json"
        $lockPath = Join-Path $root ".manifest.lock"
        New-Dir $root
        New-Dir $machinesDir
        
        # 1) Grava o JSON do host
        $hostJsonPath = Join-Path $machinesDir ("{0}.json" -f $computer)
        $jsonHost = ($report | ConvertTo-Json -Depth 12)
        AtomicWrite-Text -path $hostJsonPath -content $jsonHost
        
        # 2) Atualiza o manifesto com lock
        $lockStream = Acquire-Lock -lockPath $lockPath -tries $LockMaxTries -sleepMs $LockSleepMs
        if ($lockStream) {
            try {
                $manifest = @()
                if (Test-Path -LiteralPath $manifestPath) {
                    try {
                        $raw = Get-Content -Raw -Path $manifestPath -Encoding UTF8
                        $trim = $raw.Trim()
                        if ($trim.StartsWith("[")) { $manifest = $raw | ConvertFrom-Json -ErrorAction Stop }
                        elseif ($trim.StartsWith("{")) { $manifest = @($raw | ConvertFrom-Json -ErrorAction Stop) }
                    }
                    catch { $manifest = @() }
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
                for ($i = 0; $i -lt $manifest.Count; $i++) { if ($manifest[$i].Hostname -eq $computer) { $idx = $i; break } }
                if ($idx -ge 0) { $manifest[$idx] = $entry } else { $manifest += $entry }
                
                # Ordena por severidade e hostname
                $manifest = @($manifest | Sort-Object @{ Expression = { Get-SeverityWeight $_.Status }; Descending = $true }, Hostname)
                
                # Grava como ARRAY
                $manifestJson = ConvertTo-JsonForceArray -Collection $manifest -Depth 6
                AtomicWrite-Text -path $manifestPath -content $manifestJson
            }
            finally {
                Release-Lock -stream $lockStream -lockPath $lockPath
            }
        }
    }
    
    # Salvar no banco (se inicializado com sucesso)
    if ($dbInitialized) {
        $jsonData = $report | ConvertTo-Json -Depth 12
        $saved = Save-ToDatabase -DbPath $SQLitePath -Hostname $computer -Timestamp (Get-Date) -JsonData $jsonData -Status $report.Status -OSName $report.OS.Caption -CollectionMode $ModoColeta
        
        if (-not $saved) {
            Write-Log "Falha ao salvar em todos os métodos de banco de dados" "WARNING"
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    Write-Log "Inventário concluído com sucesso em $($duration.TotalSeconds) segundos"
    
    # Execução contínua se intervalo configurado
    if ($IntervaloExecucao -gt 0) {
        Write-Log "Aguardando próximo ciclo em $IntervaloExecucao segundos..."
        Start-Sleep -Seconds $IntervaloExecucao
        Write-Log "Reiniciando ciclo de inventário..."
        . $MyInvocation.MyCommand.Path @PSBoundParameters
    }
}
catch {
    Write-Log "Erro fatal no script: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    exit 1
}