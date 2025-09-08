# Script para startar http-server com PM2 e manter em background

$AppDir  = "\\192.168.16.3\brasilsuperatacado\sysinfo"
$Port    = 8080
$AppName = "SysInfo"

# Vai até a pasta da aplicação
Set-Location $AppDir

# Verifica se pm2 está instalado
if (-not (Get-Command pm2 -ErrorAction SilentlyContinue)) {
    npm install -g pm2
}

# Starta a aplicação com pm2
pm2 start "npx http-server . -a 0.0.0.0 -p $Port" --name $AppName

# Salva a configuração
pm2 save

# Configura para iniciar no boot
pm2 startup powershell | Invoke-Expression
