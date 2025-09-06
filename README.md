# 📊 Central de Análise de TI - Sistema de Inventário

Sistema avançado de inventário e monitoramento de recursos de TI para ambientes corporativos, proporcionando visibilidade completa sobre o estado da infraestrutura.

## 🚀 Objetivos do Projeto

- Coleta Automatizada: Inventário completo de hardware e software
- Monitoramento em Tempo Real: Alertas proativos sobre problemas críticos
- Dashboard Interativo: Visualização intuitiva do estado da infraestrutura
- Armazenamento Histórico: Persistência de dados para análise temporal
- Multiplataforma: Compatível com ambientes Windows corporativos

## 🛠️ Funcionalidades

### 🔍 Coleta de Dados
- Sistema Operacional: Versão, arquitetura, tempo de atividade
- Hardware: CPU, RAM, discos, GPU, temperaturas
- Rede: Endereços IP, MAC, configurações
- Software: Aplicativos instalados, processos em execução
- Segurança: Status de antivírus e firewall
- Eventos: Logs do sistema e aplicações

### ⚡ Alertas Automáticos
- Memória RAM: Uso excessivo e limiares críticos
- Armazenamento: Espaço em disco insuficiente
- Temperatura: Superaquecimento de componentes
- Processos: Consumo excessivo de recursos
- Serviços: Serviços críticos parados

### 📈 Visualização
- Dashboard: Visão geral do ambiente
- Gráficos Interativos: Uso de recursos e distribuição
- Detalhes Completos: Informações detalhadas por máquina
- Relatórios: Exportação em JSON e CSV

## 🏗️ Arquitetura
```powershell
text
📦 sysinfo-v2/
├── 📜 Inventario-GPO-PerHost-Avancado.ps1  # Script principal
├── 📜 index.html                           # Dashboard web
├── 📜 Install-Dependencies.ps1             # Instalador de dependências
├── 📁 machines/                            # Dados das máquinas (JSON)
├── 📁 csv_data/                            # Armazenamento alternativo (CSV)
├── 📁 alerts/                              # Registro de alertas
├── 📁 logs/                                # Logs de execução
└── 📁 libs/                                # Bibliotecas auxiliares
```

## 📋 Pré-requisitos

Requisitos Mínimos
- Windows PowerShell 5.1 ou superior
- Acesso Administrativo para coleta completa
- Política de Execução: Set-ExecutionPolicy RemoteSigned

Dependências Opcionais
- SQLite para armazenamento avançado
- Módulo PSSQLite para funcionalidades extendidas

## 🚀 Como Executar

### 1️⃣ Instalação Rápida

#### Clone ou baixe o projeto

```powershell
git clone https://github.com/castelogui/sysinfo

# Execute o instalador de dependências (como administrador)
Set-ExecutionPolicy Bypass -Scope Process -Force .\Install-Dependencies.ps1
```
### 2️⃣ Execução do Inventário

```powershell
# Modo simples (sem SQLite)
.\Inventario-GPO-PerHost-Avancado.ps1
```
```powershell
# Modo completo com todas as funcionalidades
.\Inventario-GPO-PerHost-Avancado.ps1 -ModoColeta Completo
```
```powershell
# Com agendamento automático (executa a cada hora)
.\Inventario-GPO-PerHost-Avancado.ps1 -IntervaloExecucao 3600
```

### 3️⃣ Opções de Execução

```powershell
# Coleta mínima (rápida)
.\Inventario-GPO-PerHost-Avancado.ps1 -ModoColeta Minimo
```
```powershell
# Coleta rápida (sem software e eventos)
.\Inventario-GPO-PerHost-Avancado.ps1 -ModoColeta Rapido
```
```powershell
# Ignorar verificação de temperaturas
.\Inventario-GPO-PerHost-Avancado.ps1 -SkipTemps
```
```powershell
# Usar armazenamento CSV (recomendado sem SQLite)
.\Inventario-GPO-PerHost-Avancado.ps1 -UseCSV
```
```powershell
# Desabilitar JSON (apenas banco de dados)
.\Inventario-GPO-PerHost-Avancado.ps1 -DisableJSON
```

### 4️⃣ Iniciar o Dashboard

```powershell
# Instalar servidor web globalmente (uma vez)
npm install -g http-server

# Acessar no navegador: http://localhost:8080
```
ou
```powershell
# Iniciar dashboard
npx http-server . -a 0.0.0.0 -p 8080

# Acessar no navegador: http://localhost:8080
```

## ⚙️ Configuração de Alertas

Limiares Padrão
```powershell
# Memória RAM
-MinMemFreePercent 20    # Alerta abaixo de 20%
-MinMemFreeGB 2.0        # Alerta abaixo de 2GB livre
# Disco
-MinDiskFreePercent 15   # Alerta abaixo de 15%
-MinDiskFreeGB 20.0      # Alerta abaixo de 20GB livre

# Temperatura
-HighTempWarnC 80        # Alerta acima de 80°C
-HighTempCritC 90        # Crítico acima de 90°C

# Processos
-MaxProcessCPU 90        # Alerta acima de 90% CPU
-MaxProcessMemoryMB 1024 # Alerta acima de 1GB RAM por processo
```

Exemplo com Limiares Customizados
```powershell
.\Inventario-GPO-PerHost-Avancado.ps1 `
  -MinMemFreePercent 10 `
  -MinMemFreeGB 1.0 `
  -MinDiskFreePercent 10 `
  -HighTempWarnC 70 `
  -HighTempCritC 85
```

## 🎯 Implantação Corporativa

### Via Política de Grupo (GPO)

1 - Coloque o script em um compartilhamento de rede
2 - Crie uma GPO para executar o script no startup
3 - Configure permissões adequadas para leitura/escrita

### Agendamento via Task Scheduler
```powershell
# Criar tarefa agendada
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
  -Argument "-File D:\dev\sysinfo\v2\Inventario-GPO-PerHost-Avancado.ps1 -ModoColeta Rapido"

$trigger = New-ScheduledTaskTrigger -Daily -At 9am
Register-ScheduledTask -TaskName "Inventario TI" -Action $action -Trigger $trigger -User "SYSTEM"
```
### Implantação em Lote
```powershell
# Executar em múltiplos computadores
$computers = @("PC01", "PC02", "PC03", "SERVER01")
foreach ($computer in $computers) {
    Invoke-Command -ComputerName $computer -ScriptBlock {
        \\share\sysinfo\v2\Inventario-GPO-PerHost-Avancado.ps1 -ModoColeta Completo
    }
}
```

## 📊 Estrutura de Dados
Arquivo de Manifesto (manifest.json)
```json
[
  {
    "Hostname": "PC01",
    "Json": "machines/PC01.json",
    "TimestampUtc": "2025-09-03T19:23:55.123Z",
    "Status": "OK",
    "OS": "Windows 10 Enterprise",
    "CollectionMode": "Completo"
  }
]
```

Arquivo de Máquina (machines/PC01.json)
```json
{
  "Hostname": "PC01",
  "TimestampUtc": "2025-09-03T19:23:55.123Z",
  "Status": "OK",
  "OS": {
    "Caption": "Windows 10 Enterprise",
    "Version": "10.0.19044",
    "Build": "19044",
    "Architecture": "64-bit"
  },
  "CPU": {
    "Name": "Intel Core i7-10700",
    "Cores": 8,
    "Logical": 16
  },
  "RAM": {
    "TotalGB": 32.0,
    "FreeGB": 12.5,
    "FreePercent": 39.1
  }
}
```
## 🔧 Troubleshooting

### Problemas Comuns e Soluções
Erro de Permissão
```powershell
# Executar como administrador
Start-Process PowerShell -Verb RunAs -ArgumentList "-File Inventario-GPO-PerHost-Avancado.ps1"
```
Erro de Política de Execução
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```
SQLite Não Instalado
```powershell
# Usar modo CSV que não requer SQLite
.\Inventario-GPO-PerHost-Avancado.ps1 -UseCSV
```
Problemas de Rede
```powershell
# Verificar se o compartilhamento está acessível
Test-NetConnection -ComputerName SERVER -Port 445
```
Logs e Diagnóstico
```powershell
# Verificar logs de execução
Get-ChildItem .\logs\*.log | Sort-Object LastWriteTime -Desc | Select-Object -First 1 | Get-Content

# Verificar integridade dos arquivos
Test-Path .\manifest.json
Get-ChildItem .\machines | Measure-Object | Select-Object Count
```
## 📈 Monitoramento e Manutenção
Verificação de Saúde do Sistema
```powershell
# Script de verificação automática
.\Test-SystemHealth.ps1

# Verificar espaço em disco
Get-Volume | Select-Object DriveLetter, SizeRemaining, Size

# Monitorar uso de recursos
Get-Process | Sort-Object CPU -Desc | Select-Object -First 5
```
Limpeza Automática
```powershell
# Manter apenas últimos 7 dias de dados
$limit = (Get-Date).AddDays(-7)
Get-ChildItem .\machines\*.json | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item
Get-ChildItem .\logs\*.log | Where-Object { $_.LastWriteTime -lt $limit } | Remove-Item
```
## 🤝 Contribuição e Atualizações
Estrutura do Projeto para Desenvolvedores
```powershell
text
📦 sysinfo-v2/
├── 📂 docs/                 # Documentação
├── 📂 src/                  # Código fonte
│   ├── 📂 modules/          # Módulos PowerShell
│   ├── 📂 web/              # Código do dashboard
│   └── 📂 tests/            # Testes unitários
├── 📂 dist/                 # Builds de distribuição
└── 📂 samples/              # Exemplos de uso
```
Processo de Atualização
- Testar Localmente: .\Run-Tests.ps1
- Validar em Ambiente de Teste
- Atualizar Documentação
- Distribuir via GPO/Deploy

Adicionando Novas Funcionalidades
```powershell
# 1. Criar nova função de coleta
function Get-NetworkInfo {
    # Implementação da coleta
}

# 2. Adicionar ao processo principal
$report | Add-Member -NotePropertyName "Network" -NotePropertyValue (Get-NetworkInfo)

# 3. Atualizar dashboard para exibir novos dados
```
## 📞 Suporte e Contato
Canais de Suporte
- Documentação: Consulte este README
- Issues: Reportar problemas no repositório
- Email: suporte.ti@empresa.com

## 📄 Licença
Este projeto é destinado para uso corporativo interno. Consulte o departamento de TI para informações sobre licenciamento e distribuição.

⚠️ Importante: Sempre teste em ambiente controlado antes de implantar em produção. Monitore o desempenho durante as primeiras execuções.

🔄 Última Atualização: 03/09/2025 - Versão 2.2