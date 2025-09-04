<#
 Script de instalação de dependências para o Inventário de TI
 Versão corrigida para problemas de arquitetura
#>

param(
    [switch]$Force
)

Write-Host "Instalando dependências para o Inventário de TI..." -ForegroundColor Green

# Verificar arquitetura do PowerShell
$architecture = $env:PROCESSOR_ARCHITECTURE
$is64Bit = [Environment]::Is64BitProcess
Write-Host "Arquitetura do PowerShell: $architecture (64-bit: $is64Bit)" -ForegroundColor Cyan

# Verificar se é administrador
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Este script requer privilégios de administrador. Execute como administrador."
    exit 1
}

# 1. Remover versões problemáticas do SQLite existentes
try {
    $existingModule = Get-Module -Name SQLite -ListAvailable -ErrorAction SilentlyContinue
    if ($existingModule) {
        Write-Host "Removendo módulo SQLite existente..." -ForegroundColor Yellow
        $existingModule | ForEach-Object {
            Remove-Module -Name $_.Name -Force -ErrorAction SilentlyContinue
            $modulePath = $_.ModuleBase
            if (Test-Path $modulePath) {
                Remove-Item -Path $modulePath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Módulos SQLite existentes removidos." -ForegroundColor Green
    }
}
catch {
    Write-Host "Aviso: Não foi possível remover módulos existentes: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 2. Instalar módulo SQLite alternativo mais confiável
try {
    Write-Host "Instalando módulo DBSQLite (alternativo)..." -ForegroundColor Yellow
    Install-Module -Name DBSQLite -Force -SkipPublisherCheck -ErrorAction Stop
    Import-Module DBSQLite -Force -ErrorAction Stop
    Write-Host "Módulo DBSQLite instalado com sucesso!" -ForegroundColor Green
}
catch {
    Write-Host "Erro ao instalar módulo DBSQLite: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Tentar instalar o módulo SQLite oficial com abordagem diferente
try {
    Write-Host "Tentando instalar módulo SQLite com abordagem alternativa..." -ForegroundColor Yellow
    
    # Desinstalar versões existentes primeiro
    Uninstall-Module -Name SQLite -AllVersions -ErrorAction SilentlyContinue
    
    # Instalar versão específica que pode ser mais compatível
    Install-Module -Name SQLite -RequiredVersion 1.0.113 -Force -SkipPublisherCheck -ErrorAction Stop
    
    Write-Host "Módulo SQLite instalado com sucesso!" -ForegroundColor Green
}
catch {
    Write-Host "Erro ao instalar módulo SQLite: $($_.Exception.Message)" -ForegroundColor Red
}

# 4. Método manual - Baixar a DLL correta diretamente
try {
    Write-Host "`nTentando método manual de instalação..." -ForegroundColor Yellow
    
    # Criar diretório para bibliotecas
    $libsPath = "$PSScriptRoot\libs"
    New-Item -ItemType Directory -Path $libsPath -Force | Out-Null
    
    # Determinar URL correta baseada na arquitetura
    if ($is64Bit) {
        $sqliteUrl = "https://www.sqlite.org/2023/sqlite-dll-win-x64-3440200.zip"
        Write-Host "Baixando DLL SQLite 64-bit..." -ForegroundColor Cyan
    }
    else {
        $sqliteUrl = "https://www.sqlite.org/2023/sqlite-dll-win-x86-3440200.zip"
        Write-Host "Baixando DLL SQLite 32-bit..." -ForegroundColor Cyan
    }
    
    $zipPath = "$env:TEMP\sqlite-dll.zip"
    $extractPath = "$env:TEMP\sqlite-extract"
    
    # Download
    Invoke-WebRequest -Uri $sqliteUrl -OutFile $zipPath -ErrorAction Stop
    
    # Extrair
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
    
    # Copiar DLLs
    Get-ChildItem -Path $extractPath -Filter "*.dll" | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $libsPath -Force
        Copy-Item -Path $_.FullName -Destination $PSScriptRoot -Force
        Write-Host "Copiado: $($_.Name)" -ForegroundColor Green
    }
    
    # Limpar
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "DLLs do SQLite baixadas manualmente com sucesso!" -ForegroundColor Green
}
catch {
    Write-Host "Erro no método manual: $($_.Exception.Message)" -ForegroundColor Red
}

# 5. Instalar módulos PowerShell necessários
$requiredModules = @(
    @{Name = "PSWriteColor"; Version = "1.0.1"},
    @{Name = "ImportExcel"; Version = "7.8.6"},
    @{Name = "PSSQLite"; Version = "1.0.3"}  # Módulo alternativo
)

foreach ($module in $requiredModules) {
    try {
        if (-not (Get-Module -ListAvailable -Name $module.Name)) {
            Write-Host "Instalando módulo $($module.Name)..." -ForegroundColor Yellow
            Install-Module -Name $module.Name -Force -SkipPublisherCheck -ErrorAction Stop
            Write-Host "Módulo $($module.Name) instalado com sucesso!" -ForegroundColor Green
        }
        else {
            Write-Host "Módulo $($module.Name) já está instalado." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro ao instalar módulo $($module.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 6. Testar a instalação
Write-Host "`nTestando instalação..." -ForegroundColor Cyan

try {
    # Testar com PSSQLite (alternativo)
    Import-Module PSSQLite -Force -ErrorAction Stop
    Write-Host "✓ Módulo PSSQLite carregado com sucesso" -ForegroundColor Green
    
    # Testar criação de banco simples
    $testDbPath = "$PSScriptRoot\test.db"
    if (Test-Path $testDbPath) { Remove-Item $testDbPath -Force }
    
    $conn = New-SQLiteConnection -DataSource $testDbPath
    $conn.Open()
    $command = $conn.CreateCommand()
    $command.CommandText = "CREATE TABLE test (id INTEGER, name TEXT)"
    $command.ExecuteNonQuery()
    $conn.Close()
    
    Remove-Item $testDbPath -Force
    Write-Host "✓ Teste de banco de dados bem-sucedido" -ForegroundColor Green
}
catch {
    Write-Host "✗ Teste falhou: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nInstalação concluída! Agora você pode executar o script principal." -ForegroundColor Green
Write-Host "Execute: .\Inventario-GPO-PerHost-Avancado.ps1" -ForegroundColor Cyan
Write-Host "`nSe ainda houver problemas, execute: .\Inventario-GPO-PerHost-Avancado.ps1 -UsePSSQLite" -ForegroundColor Yellow