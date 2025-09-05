# PSEXEC-EXECUTE-MANIFEST-CORRIGIDO.ps1
# Usando caminhos completos para os executáveis
# Certifique-se de que o PsExec.exe está no PATH do sistema ou forneça o caminho completo para ele
# Script para executar comandos remotamente usando PsExec com base em um manifesto JSON

$manifest = Get-Content "\manifest.json" | ConvertFrom-Json
$command = "PowerShell.exe -ExecutionPolicy Bypass -File '\\brasildis.lan\SYSVOL\brasildis.lan\Policies\{1C3C1FF0-24E1-4161-A388-E5FDBB00ABCF}\User\Scripts\Logon\GPO-COMPLETE-SYSINFO.ps1'"

foreach ($item in $manifest) {
  $hostname = $item.Hostname
  if ($hostname) {
    Write-Host "Processando host: $hostname" -ForegroundColor Yellow
    $psexecCommand = "PsExec.exe \\$hostname -s -d $command"
    Write-Host "Executando comando: $command" -ForegroundColor Green
    Invoke-Expression $psexecCommand
  }
}
