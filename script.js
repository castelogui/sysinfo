// Variáveis globais
let ambienteProducao = false;
let allMachines = [];
let allAlerts = [];
let currentTheme = localStorage.getItem('theme') || 'light';
let currentView = 'dashboard';
let currentMetric = 'memory';
let currentChartType = 'doughnut';
const modal = document.getElementById('machine-modal');

/* ====== INÍCIO: Anti-cache (adicionado) ====== */
const NO_CACHE_INIT = {
  cache: 'no-store',
  headers: {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'Expires': '0'
  }
};

function bust(url) {
  try {
    const u = new URL(url, window.location.href);
    // parâmetro único por requisição
    u.searchParams.set('_', Date.now().toString());
    return u.toString();
  } catch {
    const sep = url.includes('?') ? '&' : '?';
    return `${url}${sep}_=${Date.now()}`;
  }
}
/* ====== FIM: Anti-cache (adicionado) ====== */

async function fetchConfig() {
  try {
    const configResponse = await fetch(bust('./config.json'), NO_CACHE_INIT);
    if (!configResponse.ok) {
      throw new Error(`Erro HTTP ${configResponse.status}: ${configResponse.statusText}`);
    }
    config = await configResponse.json();
    return config;
  } catch (error) {
    console.error('Erro ao carregar configuração: ', error);
    const configResponse = await fetch(bust('./config_exemple.json'), NO_CACHE_INIT);
    if (!configResponse.ok) {
      throw new Error(`Erro HTTP ${configResponse.status}: ${configResponse.statusText}`);
    }
    config = await configResponse.json();
    return config;
  }
}

// Aplicar tema salvo
if (currentTheme === 'dark') {
  document.body.classList.add('dark-theme');
}

// Inicializar gráficos
let resourcesChart = null;
let statusChart = null;
let alertsChart = null;

// Função para carregar dados das máquinas
async function loadMachinesData() {
  try {
    allMachines = [];
    showLoading('machines-container', 'Carregando dados das máquinas...');

    // Carregar manifesto
    let manifest = [];
    try {
      if (ambienteProducao) {
        try {
          const manifestResponse = await fetch(bust('manifest.json'), NO_CACHE_INIT);
          if (!manifestResponse.ok) {
            throw new Error(`Erro HTTP ${manifestResponse.status}: ${manifestResponse.statusText}`);
          }

          manifest = await manifestResponse.json();
        } catch (error) {
          console.error('Erro ao carregar manifesto oficial:', error);
        }
      } else {
        try {
          console.log('Carregando manifesto alternativo...');
          const manifestResponse = await fetch(bust('manifest_exemple.json'), NO_CACHE_INIT);
          if (!manifestResponse.ok) {
            throw new Error(`Erro HTTP ${manifestResponse.status}: ${manifestResponse.statusText}`);
          }

          manifest = await manifestResponse.json();
        } catch (error) {
          console.error('Erro ao carregar manifesto alternativo:', error);
        }
      }
    } catch (error) {
      console.error('Erro ao carregar manifesto:', error);
      showError('machines-container', 'Erro ao carregar manifesto. Execute o script PowerShell primeiro.');
      return;
    }

    // Carregar dados de cada máquina
    for (const entry of manifest) {
      try {
        const machineResponse = await fetch(bust(entry.Json), NO_CACHE_INIT);
        if (!machineResponse.ok) {
          console.error(`Erro ao carregar ${entry.Json}: ${machineResponse.status}`);
          continue;
        }

        const machineData = await machineResponse.json();
        if (Array.isArray(machineData)) {
          machineData.forEach(m => {
            if (m?.Hostname) allMachines.push(m)
          });
        } else {
          allMachines.push(machineData);
        }
      } catch (error) {
        console.error(`Erro ao processar máquina ${entry.Hostname}:`, error);
      }
    }

    if (allMachines.length === 0) {
      showEmptyState('machines-container', 'Nenhuma máquina encontrada', 'Execute o script PowerShell para gerar os dados de inventário.');
      return;
    }

    updateStats();
    if (currentView === 'machines') {
      renderMachines(allMachines);
    }

    // Processar alertas a partir dos dados das máquinas
    processAlertsFromMachines();

    // Atualizar gráficos
    updateResourcesChart();
    updateStatusChart();
    updateAlertsChart();

  } catch (error) {
    console.error('Erro ao carregar dados:', error);
    showError('machines-container', error);
  }
}

// Processar alertas a partir dos dados das máquinas
function processAlertsFromMachines() {
  allAlerts = [];

  allMachines.forEach(machine => {
    // Alertas críticos
    if (machine.IssuesCrit && machine.IssuesCrit.length > 0) {
      machine.IssuesCrit.forEach(issue => {
        allAlerts.push({
          hostname: machine.Hostname,
          alert_type: getAlertTypeFromIssue(issue),
          alert_message: issue,
          alert_severity: 'Crítico',
          alert_time: machine.TimestampUtc
        });
      });
    }

    // Alertas de atenção
    if (machine.IssuesWarn && machine.IssuesWarn.length > 0) {
      machine.IssuesWarn.forEach(issue => {
        allAlerts.push({
          hostname: machine.Hostname,
          alert_type: getAlertTypeFromIssue(issue),
          alert_message: issue,
          alert_severity: 'Atenção',
          alert_time: machine.TimestampUtc
        });
      });
    }
  });

  // Ordenar alertas por tempo (mais recente primeiro)
  allAlerts.sort((a, b) => new Date(b.alert_time) - new Date(a.alert_time));

  if (currentView === 'dashboard') {
    updateAlertsPanel();
  } else if (currentView === 'alerts') {
    renderAlertsPanel();
  }
}

// Função auxiliar para determinar o tipo de alerta a partir da mensagem
function getAlertTypeFromIssue(issue) {
  if (issue.includes('RAM')) return 'RAM';
  if (issue.includes('Disco') || issue.includes('espaço')) return 'Disco';
  if (issue.includes('Temperatura')) return 'Temperatura';
  if (issue.includes('Processo')) return 'Processo';
  if (issue.includes('Serviço')) return 'Serviço';
  return 'Sistema';
}

// Função para renderizar as máquinas
function renderMachines(machines) {
  const container = document.getElementById('machines-container');

  if (!machines || machines.length === 0) {
    showEmptyState('machines-container', 'Nenhuma máquina encontrada', 'Execute o script PowerShell para gerar os dados de inventário.');
    return;
  }

  container.innerHTML = '';

  machines.forEach(machine => {
    const card = createMachineCard(machine);
    container.appendChild(card);
  });
}

// Função para criar o card de uma máquina
function createMachineCard(machine) {
  const card = document.createElement('div');
  card.className = 'machine-card';
  card.id = `machine-${machine.Hostname}`;

  // Determina a classe de status
  let statusClass = 'status-ok';
  if (machine.Status === 'Atenção') statusClass = 'status-warning';
  if (machine.Status === 'Crítico') statusClass = 'status-critical';

  // Encontra o volume do sistema (C:)
  const systemDrive = machine.Storage?.Volumes?.find(v => v.DriveLetter === 'C') ||
    (machine.Storage?.Volumes?.length > 0 ? machine.Storage.Volumes[0] : null);

  // Formata a data
  const formattedDate = formatDate(machine.TimestampUtc);

  card.innerHTML = `
        <div class="card-header">
          <h3>${machine.Hostname}</h3>
          <span class="status-badge ${statusClass}">${machine.Status}</span>
        </div>
        <div class="card-body">
          <div class="info-item">
            <div class="info-label"><i class="fas fa-desktop"></i> Sistema Operacional</div>
            <div>${machine.OS?.Caption || 'N/A'}</div>
          </div>
          
          <div class="info-item">
            <div class="info-label"><i class="fas fa-desktop"></i> Computador</div>
            <div>${machine.Computer?.Manufacturer || 'N/A'} ${machine.Computer?.Family || 'N/A'}</div>
          </div>
          
          <div class="info-item">
            <div class="info-label"><i class="fas fa-microchip"></i> Processador</div>
            <div>${machine.CPU?.Name || 'N/A'}</div>
          </div>

          <div class="info-item">
            <div class="info-label"><i class="fas fa-exclamation-triangle"></i> Alertas</div>
            <div>
              <ul>
                ${machine.IssuesCrit.map(issue => `<li style="list-style-type: none;"><i class="fas fa-exclamation-circle" style="color: var(--danger);"></i> ${issue}</li>`).join('')}
              </ul>
              <ul>
                ${machine.IssuesWarn.map(issue => `<li style="list-style-type: none;"><i class="fas fa-exclamation-triangle" style="color: var(--warning);"></i> ${issue}</li>`).join('')}
              </ul>
            </div>
          </div>
          
          <div class="info-item">
            <div class="info-label"><i class="fas fa-memory"></i> Memória RAM</div>
            <div>${machine.RAM?.TotalGB || 'N/A'} GB (${machine.RAM?.FreeGB || 'N/A'} GB livre)</div>
            ${machine.RAM?.FreePercent ? `
              <div class="progress-bar">
                <div class="progress-fill ${getProgressClass(100 - machine.RAM.FreePercent)}" 
                     style="width: ${100 - machine.RAM.FreePercent}%"></div>
              </div>
            ` : ''}
          </div>
          
          ${systemDrive ? `
          <div class="info-item">
            <div class="info-label"><i class="fas fa-hdd"></i> Armazenamento (${systemDrive.DriveLetter})</div>
            <div>Livre: ${systemDrive.FreeGB} GB de ${systemDrive.SizeGB} GB</div>
            <div class="progress-bar">
              <div class="progress-fill ${getProgressClass(100 - systemDrive.FreePercent)}" 
                   style="width: ${100 - systemDrive.FreePercent}%"></div>
            </div>
          </div>
          ` : ''}
          
          ${machine.Temps?.MaxC ? `
          <div class="info-item">
            <div class="info-label"><i class="fas fa-thermometer-half"></i> Temperatura</div>
            <div>Máxima: ${machine.Temps.MaxC}°C</div>
          </div>
          ` : ''}
        </div>
        <div class="card-footer">
          <span class="timestamp">${formattedDate}</span>
          <button class="btn btn-outline btn-sm view-details-btn" data-hostname="${machine.Hostname}">
            <i class="fas fa-info-circle"></i> Detalhes
          </button>
        </div>
      `;

  // Adicionar evento ao botão de detalhes
  const detailsBtn = card.querySelector('.view-details-btn');
  detailsBtn.addEventListener('click', () => {
    showMachineDetails(machine);
  });

  return card;
}

// Função para exibir os detalhes da máquina em um modal
function showMachineDetails(machine) {
  const modalTitle = document.getElementById('modal-title');
  const modalBody = document.getElementById('modal-body');

  modalTitle.textContent = machine.Hostname;
  modalBody.innerHTML = createDetailsContent(machine);

  modal.style.display = 'block';
  document.body.style.overflow = 'hidden';
}

// Função para obter a classe de progresso com base no percentual
function getProgressClass(percent) {
  if (percent > 90) return 'progress-danger';
  if (percent > 75) return 'progress-warning';
  return 'progress-normal';
}

// Função para criar o conteúdo detalhado
function createDetailsContent(machine) {
  let detailsHTML = '';

  // Abas
  detailsHTML += `
        <div class="tab-container">
          <div class="tab-buttons">
            <button class="tab-btn active" data-tab="overview">Visão Geral</button>
            <button class="tab-btn" data-tab="hardware">Hardware</button>
            <button class="tab-btn" data-tab="software">Software</button>
            <button class="tab-btn" data-tab="network">Rede</button>
            <button class="tab-btn" data-tab="events">Eventos</button>
            <button class="tab-btn" data-tab="security">Segurança</button>
          </div>
          
          <div class="tab-content active" id="tab-overview">
      `;

  // Visão Geral
  detailsHTML += `
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-item-label">Status</div>
            <div class="detail-item-value"><span class="status-badge ${machine.Status === 'OK' ? 'status-ok' : machine.Status === 'Atenção' ? 'status-warning' : 'status-critical'}">${machine.Status}</span></div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Última Atualização</div>
            <div class="detail-item-value">${formatDate(machine.TimestampUtc)}</div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Modo de Coleta</div>
            <div class="detail-item-value">${machine.CollectionMode || 'N/A'}</div>
          </div>
          <div class="detail-item">
            <div class="detail-item-label">Versão do Script</div>
            <div class="detail-item-value">${machine.ScriptVersion || 'N/A'}</div>
          </div>
        </div>
        <div class="detail-content">
          <div class="detail-section">
            <h4><i class="fas fa-desktop"></i> Sistema Operacional</h4>
            <p><strong>Nome:</strong> ${machine.OS?.Caption || 'N/A'}</p>
            <p><strong>Versão:</strong> ${machine.OS?.Version || 'N/A'}</p>
            <p><strong>Build:</strong> ${machine.OS?.Build || 'N/A'}</p>
            <p><strong>Arquitetura:</strong> ${machine.OS?.Architecture || 'N/A'}</p>
            <p><strong>Instalado em:</strong> ${formatDateMS(machine.OS?.InstallDate) || 'N/A'}</p>
            <p><strong>Último boot:</strong> ${formatDateMS(machine.OS?.LastBoot) || 'N/A'}</p>
            <p><strong>Uptime:</strong> ${machine.OS?.Uptime || 'N/A'}</p>
            <p><strong>Usuário Logado:</strong> ${machine.Computer?.User || 'N/A'}</p>
          </div>
          <div class="detail-section">
            <h4><i class="fas fa-desktop"></i> Computador</h4>
            <p><strong>Marca: </strong>${machine.Computer?.Manufacturer || 'N/A'}</p>
            <p><strong>Modelo: </strong>${machine.Computer?.Family || 'N/A'}</p>
            <p><strong>S/N: </strong>${machine.Computer?.Serial || 'N/A'}</p>
          </div>
        </div>
        `;

  // Hardware
  detailsHTML += `
          </div>
          <div class="tab-content" id="tab-hardware">
          
            <div class="detail-content">
              <div class="detail-section">
                <h4><i class="fas fa-microchip"></i> Processador</h4>
                <p><strong>Nome:</strong> ${machine.CPU?.Name || 'N/A'}</p>
                <p><strong>Núcleos:</strong> ${machine.CPU?.Cores || 'N/A'} cores, ${machine.CPU?.Logical || 'N/A'} threads</p>
                <p><strong>Clock Máximo:</strong> ${machine.CPU?.MaxClockMHz || 'N/A'} MHz</p>
              </div>

              <div class="detail-section">
                <h4><i class="fas fa-microchip"></i> Placa de Vídeo</h4>
                <p><strong>Nome:</strong> ${machine.GPU?.Name || 'N/A'}</p>
                <p><strong>VRAM:</strong> ${machine.GPU?.VRAM_GB || 'N/A'} GB</p>
                <p><strong>Resolução:</strong> ${machine.GPU?.Resolution || 'N/A'}</p>
              </div>
            </div>
            
            <div class="detail-content">
              <div class="detail-section">
                <h4><i class="fas fa-memory"></i> Memória RAM</h4>
                <p><strong>Total:</strong> ${machine.RAM?.TotalGB || 'N/A'} GB</p>
                <p><strong>Livre:</strong> ${machine.RAM?.FreeGB || 'N/A'} GB (${machine.RAM?.FreePercent || 'N/A'}%)</p>
            `;

  if (machine.RAM?.Modules && machine.RAM.Modules.length > 0) {
    detailsHTML += `<h5>Módulos:</h5>`;
    const ddrMap = { 20:'DDR', 21:'DDR2', 24:'DDR3', 26:'DDR4', 30:'DDR5', 34:'DDR5' };
    
    // Converte valor para DDRx ou N/A
    const asDdr = (val) => {
      if (val === undefined || val === null) return 'N/A';
      const s = String(val).trim();
      if (!s) return 'N/A';
      const n = Number(s);
      if (!Number.isNaN(n)) return ddrMap[n] || 'N/A';
      const up = s.toUpperCase();
      return up.startsWith('DDR') ? up : 'N/A';
    };
    machine.RAM.Modules.forEach(module => {
      detailsHTML += `
                <div style="margin-left: 20px; margin-bottom: 10px;">
                <p><strong>Capacidade:</strong> ${module.CapacityGB || 'N/A'} GB</p>
                <p><strong>Velocidade:</strong> ${module.SpeedMHz || 'N/A'} MHz</p>
                <p><strong>Tipo:</strong> ${asDdr(module.Type ?? module.SMBIOSType ?? module.SMBIOSMemoryType)}</p>
                <p><strong>Fabricante:</strong> ${module.Manuf || 'N/A'}</p>
                <p><strong>Part Number:</strong> ${module.Part || 'N/A'}</p>
                  <p><strong>Banco:</strong> ${module.Bank || 'N/A'}</p>
                  <p><strong>Slot:</strong> ${module.Slot || 'N/A'}</p>
                </div>
                <br/>
              `;
    });
  }
  detailsHTML += `
              </div>
              <div class="detail-section">
                      <h4><i class="fas fa-microchip"></i> Armazenamento</h4>
                      <h5>Volumes:</h5>
                      `
              machine.Storage?.Volumes?.forEach(volume => {
                detailsHTML += `
                      <div style="margin-left: 20px; margin-bottom: 10px;">
                        <p><strong>Drive:</strong> ${volume.DriveLetter || 'N/A'}: ${volume.Label}</p>
                        <p><strong>Sistema de Arquivos:</strong> ${volume.FileSystem || 'N/A'}</p>
                        <p><strong>Capacidade:</strong> ${volume.SizeGB || 'N/A'} GB | Livre: ${volume.FreeGB || 'N/A'} GB (${volume.FreePercent || 'N/A'}%)</p>
                      </div>
                      <br/>`
                    });
              detailsHTML += `<h5>Discos:</h5>`;
              machine.Storage?.Disks?.forEach(disk => {
                detailsHTML += `
                      <div style="margin-left: 20px; margin-bottom: 10px;">
                        <p><strong>Tipo:</strong> ${disk.Type || 'N/A'} ${disk.Model || 'N/A'}</p>
                        <p><strong>S/N:</strong> ${disk.Serial || 'N/A'}</p>
                        <p><strong>Capacidade:</strong> ${disk.SizeGB || 'N/A'} GB</p>
                      </div>
                      <br/>
                    `;
              });
  detailsHTML += `
        </div>
      </div>`;

  // Software
  detailsHTML += `
          </div>
          <div class="tab-content" id="tab-software">
      `;

  if (machine.Processes && machine.Processes.length > 0) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-tasks"></i> Processos (Top ${machine.Processes.length})</h4>
              <div class="table-responsive">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Nome</th>
                      <th>PID</th>
                      <th>CPU %</th>
                      <th>Memória (MB)</th>
                    </tr>
                  </thead>
                  <tbody>
        `;

    machine.Processes.forEach(process => {
      detailsHTML += `
                    <tr>
                      <td>${process.Name}</td>
                      <td>${process.ID}</td>
                      <td>${process.CPU || 'N/A'}</td>
                      <td>${process.MemoryMB || 'N/A'}</td>
                    </tr>
          `;
    });

    detailsHTML += `
                  </tbody>
                </table>
              </div>
            </div>
        `;
  }

  if (machine.Services && machine.Services.length > 0) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-cogs"></i> Serviços</h4>
              <div class="table-responsive">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Nome</th>
                      <th>Status</th>
                      <th>Tipo de Inicialização</th>
                    </tr>
                  </thead>
                  <tbody>
        `;

    machine.Services.forEach(service => {
      detailsHTML += `
                    <tr>
                      <td>${service.Name}</td>
                      <td><span class="status-badge ${service.Status === 'Running' ? 'status-ok' : 'status-warning'}">${service.Status}</span></td>
                      <td>${service.StartType || 'N/A'}</td>
                    </tr>
          `;
    });

    detailsHTML += `
                  </tbody>
                </table>
              </div>
            </div>
        `;
  }

  if (machine.Software && machine.Software.length > 0) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-box"></i> Software Instalado</h4>
              <div class="table-responsive">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Nome</th>
                      <th>Versão</th>
                      <th>Publicador</th>
                      <th>Tamanho (MB)</th>
                    </tr>
                  </thead>
                  <tbody>
        `;

    machine.Software.forEach(software => {
      detailsHTML += `
                    <tr>
                      <td>${software.Name}</td>
                      <td>${software.Version || 'N/A'}</td>
                      <td>${software.Publisher || 'N/A'}</td>
                      <td>${software.SizeMB || 'N/A'}</td>
                    </tr>
          `;
    });

    detailsHTML += `
                  </tbody>
                </table>
              </div>
            </div>
        `;
  }

  // Rede
  detailsHTML += `
          </div>
          <div class="tab-content" id="tab-network">
      `;

  if (machine.Network) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-network-wired"></i> Rede</h4>
              ${machine.Network.IPv4 && machine.Network.IPv4.length > 0 ? `
                <p><strong>Endereços IPv4:</strong> ${machine.Network.IPv4.join(', ') || 'N/A'}</p>
              ` : ''}
              ${machine.Network.MACs && machine.Network.MACs.length > 0 ? `
                <p><strong>Endereços MAC:</strong> ${machine.Network.MACs.join(', ') || 'N/A'}</p>
              ` : ''}
            </div>
        `;
  }

  // Eventos
  detailsHTML += `
          </div>
          <div class="tab-content" id="tab-events">
      `;

  if (machine.EventLogs && machine.EventLogs.length > 0) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-clipboard-list"></i> Logs de Eventos</h4>
              <div class="table-responsive">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Data/Hora</th>
                      <th>Log</th>
                      <th>Nível</th>
                      <th>Fonte</th>
                      <th>Evento</th>
                    </tr>
                  </thead>
                  <tbody>
        `;

    machine.EventLogs.forEach(event => {
      detailsHTML += `
                    <tr>
                      <td>${formatDateMS(event.TimeCreated)}</td>
                      <td>${event.LogName}</td>
                      <td><span class="status-badge ${event.Level === 'Crítico' ? 'status-critical' : 'status-warning'}">${event.Level}</span></td>
                      <td>${event.Provider}</td>
                      <td>${event.Message}</td>
                    </tr>
          `;
    });

    detailsHTML += `
                  </tbody>
                </table>
              </div>
            </div>
        `;
  }

  // Segurança
  detailsHTML += `
          </div>
          <div class="tab-content" id="tab-security">
      `;

  if (machine.Security) {
    if (machine.Security.Antivirus && machine.Security.Antivirus.length > 0) {
      detailsHTML += `
              <div class="detail-section">
                <h4><i class="fas fa-shield-alt"></i> Antivírus</h4>
                <div class="table-responsive">
                  <table class="table">
                    <thead>
                      <tr>
                        <th>Nome</th>
                        <th>Estado</th>
                        <th>Atualização</th>
                      </tr>
                    </thead>
                    <tbody>
          `;

      machine.Security.Antivirus.forEach(av => {
        detailsHTML += `
                      <tr>
                        <td>${av.Name}</td>
                        <td><span class="status-badge ${av.State === 'Ativo' ? 'status-ok' : 'status-warning'}">${av.State}</span></td>
                        <td>${av.Updated}</td>
                      </tr>
            `;
      });

      detailsHTML += `
                    </tbody>
                  </table>
                </div>
              </div>
          `;
    }

    if (machine.Security.Firewall && machine.Security.Firewall.length > 0) {
      detailsHTML += `
              <div class="detail-section">
                <h4><i class="fas fa-fire"></i> Firewall</h4>
                <div class="table-responsive">
                  <table class="table">
                    <thead>
                      <tr>
                        <th>Perfil</th>
                        <th>Habilitado</th>
                        <th>Entrada Padrão</th>
                        <th>Saída Padrão</th>
                      </tr>
                    </thead>
                    <tbody>
          `;

      machine.Security.Firewall.forEach(fw => {
        detailsHTML += `
                      <tr>
                        <td>${fw.Profile}</td>
                        <td><span class="status-badge ${fw.Enabled ? 'status-ok' : 'status-warning'}">${fw.Enabled ? 'Sim' : 'Não'}</span></td>
                        <td>${fw.DefaultIn}</td>
                        <td>${fw.DefaultOut}</td>
                      </tr>
            `;
      });

      detailsHTML += `
                    </tbody>
                  </table>
                </div>
              </div>
          `;
    }
  }

  // Problemas reportados
  if (machine.IssuesCrit && machine.IssuesCrit.length > 0) {
    detailsHTML += `
          <div class="detail-content">
            <div class="detail-section">
              <h4><i class="fas fa-exclamation-circle" style="color: var(--danger);"></i> Problemas Críticos</h4>
              <ul>
                ${machine.IssuesCrit.map(issue => `<li>${issue}</li>`).join('')}
              </ul>
            </div>
        `;
  }

  if (machine.IssuesWarn && machine.IssuesWarn.length > 0) {
    detailsHTML += `
            <div class="detail-section">
              <h4><i class="fas fa-exclamation-triangle" style="color: var(--warning);"></i> Alertas</h4>
              <ul>
                ${machine.IssuesWarn.map(issue => `<li>${issue}</li>`).join('')}
              </ul>
            </div>
          </div>
        `;
  }

  detailsHTML += `
          </div>
        </div>
      `;

  return detailsHTML;
}

// Função para atualizar as estatísticas
function updateStats() {
  const total = allMachines.length;
  const ok = allMachines.filter(m => m.Status === 'OK').length;
  const warning = allMachines.filter(m => m.Status === 'Atenção').length;
  const critical = allMachines.filter(m => m.Status === 'Crítico').length;

  document.getElementById('total-machines').textContent = total;
  document.getElementById('ok-machines').textContent = ok;
  document.getElementById('warning-machines').textContent = warning;
  document.getElementById('critical-machines').textContent = critical;
  document.getElementById('machine-count').textContent = `${total} máquinas`;
}

// Função para atualizar o gráfico de recursos
function updateResourcesChart() {
  const ctx = document.getElementById('resources-chart').getContext('2d');

  if (resourcesChart) {
    resourcesChart.destroy();
  }

  // Coletar dados de todas as máquinas
  const memoryData = [];
  const diskData = [];
  const tempData = [];
  const labels = [];

  allMachines.forEach(machine => {
    labels.push(machine.Hostname);

    // Dados de memória
    if (machine.RAM && machine.RAM.FreePercent !== null && machine.RAM.FreePercent !== undefined) {
      memoryData.push(100 - machine.RAM.FreePercent);
    } else {
      memoryData.push(0);
    }

    // Dados de disco
    if (machine.Storage && machine.Storage.Volumes && machine.Storage.Volumes.length > 0) {
      const mainDrive = machine.Storage.Volumes.find(v => v.DriveLetter === 'C') || machine.Storage.Volumes[0];
      if (mainDrive && mainDrive.FreePercent !== null && mainDrive.FreePercent !== undefined) {
        diskData.push(100 - mainDrive.FreePercent);
      } else {
        diskData.push(0);
      }
    } else {
      diskData.push(0);
    }

    // Dados de temperatura
    if (machine.Temps && machine.Temps.MaxC !== null && machine.Temps.MaxC !== undefined) {
      tempData.push(machine.Temps.MaxC);
    } else {
      tempData.push(0);
    }
  });

  let dataset;
  if (currentMetric === 'memory') {
    dataset = {
      label: 'Uso de Memória (%)',
      data: memoryData,
      backgroundColor: 'rgba(67, 97, 238, 0.6)',
      borderColor: '#4361ee',
      borderWidth: 1
    };
  } else if (currentMetric === 'disk') {
    dataset = {
      label: 'Uso de Disco (%)',
      data: diskData,
      backgroundColor: 'rgba(247, 37, 133, 0.6)',
      borderColor: '#f72585',
      borderWidth: 1
    };
  } else {
    dataset = {
      label: 'Temperatura Máxima (°C)',
      data: tempData,
      backgroundColor: 'rgba(230, 57, 70, 0.6)',
      borderColor: '#e63946',
      borderWidth: 1
    };
  }

  const data = {
    labels: labels,
    datasets: [dataset]
  };

  resourcesChart = new Chart(ctx, {
    type: 'bar',
    data: data,
    options: {
      responsive: true,
      plugins: {
        title: {
          display: true,
          text: currentMetric === 'memory' ? 'Uso de Memória por Máquina' :
            currentMetric === 'disk' ? 'Uso de Disco por Máquina' : 'Temperatura por Máquina'
        },
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: currentMetric === 'memory' ? 'Percentual (%)' :
              currentMetric === 'disk' ? 'Percentual (%)' : 'Temperatura (°C)'
          }
        }
      }
    }
  });
}

// Função para atualizar o gráfico de status
function updateStatusChart() {
  const ctx = document.getElementById('status-chart').getContext('2d');

  if (statusChart) {
    statusChart.destroy();
  }

  const ok = allMachines.filter(m => m.Status === 'OK').length;
  const warning = allMachines.filter(m => m.Status === 'Atenção').length;
  const critical = allMachines.filter(m => m.Status === 'Crítico').length;

  const data = {
    labels: ['OK', 'Atenção', 'Crítico'],
    datasets: [{
      data: [ok, warning, critical],
      backgroundColor: [
        '#4cc9f0',
        '#f72585',
        '#e63946'
      ],
      borderWidth: 1
    }]
  };

  statusChart = new Chart(ctx, {
    type: currentChartType,
    data: data,
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: 'top',
        },
        title: {
          display: true,
          text: 'Distribuição de Status das Máquinas'
        }
      }
    }
  });
}

// Função para atualizar o gráfico de alertas
function updateAlertsChart() {
  const ctx = document.getElementById('alerts-chart').getContext('2d');

  if (alertsChart) {
    alertsChart.destroy();
  }

  // Agrupar alertas por tipo
  const alertCounts = {
    'RAM': 0,
    'Disco': 0,
    'Temperatura': 0,
    'Processo': 0,
    'Serviço': 0,
    'Sistema': 0
  };

  allAlerts.forEach(alert => {
    if (alertCounts[alert.alert_type] !== undefined) {
      alertCounts[alert.alert_type]++;
    } else {
      alertCounts['Sistema']++;
    }
  });

  const labels = Object.keys(alertCounts).filter(key => alertCounts[key] > 0);
  const data = labels.map(label => alertCounts[label]);

  const chartData = {
    labels: labels,
    datasets: [{
      label: 'Alertas por Tipo',
      data: data,
      backgroundColor: [
        '#4361ee',
        '#4cc9f0',
        '#f72585',
        '#e63946',
        '#3a0ca3',
        '#6c757d'
      ],
      borderWidth: 1
    }]
  };

  alertsChart = new Chart(ctx, {
    type: 'doughnut',
    data: chartData,
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: 'top',
        },
        title: {
          display: true,
          text: 'Alertas por Tipo'
        }
      }
    }
  });
}

// Função para atualizar o painel de alertas
function updateAlertsPanel() {
  const container = document.getElementById('alerts-container');

  if (!allAlerts || allAlerts.length === 0) {
    container.innerHTML = `
          <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <p>Nenhum alerta ativo</p>
          </div>
        `;
    return;
  }

  container.innerHTML = '';

  // Mostrar apenas os 5 alertas mais recentes
  const recentAlerts = allAlerts.slice(0, 5);

  recentAlerts.forEach(alert => {
    const alertElement = document.createElement('div');
    alertElement.className = `alert-item ${alert.alert_severity === 'Crítico' ? 'alert-critical' : 'alert-warning'}`;

    alertElement.innerHTML = `
          <div class="alert-header">
            <div class="alert-title">${alert.alert_type} - ${alert.alert_severity}</div>
            <div class="alert-time">${formatDate(alert.alert_time)}</div>
          </div>
          <div class="alert-message">${alert.hostname}: ${alert.alert_message}</div>
        `;

    container.appendChild(alertElement);
  });
}

// Função para renderizar o painel de alertas
function renderAlertsPanel() {
  const container = document.getElementById('alerts-container');

  if (!allAlerts || allAlerts.length === 0) {
    container.innerHTML = `
          <div class="empty-state">
            <i class="fas fa-check-circle"></i>
            <p>Nenhum alerta encontrado</p>
          </div>
        `;
    return;
  }

  container.innerHTML = '';

  allAlerts.forEach(alert => {
    const alertElement = document.createElement('div');
    alertElement.className = `alert-item ${alert.alert_severity === 'Crítico' ? 'alert-critical' : 'alert-warning'}`;

    alertElement.innerHTML = `
          <div class="alert-header">
            <div class="alert-title">${alert.alert_type} - ${alert.alert_severity}</div>
            <div class="alert-time">${formatDate(alert.alert_time)}</div>
          </div>
          <div class="alert-message">${alert.hostname}: ${alert.alert_message}</div>
        `;

    container.appendChild(alertElement);
  });
}

// Função para filtrar máquinas
function filterMachines() {
  switchView('machines');
  const searchText = document.getElementById('search-input').value.toLowerCase();
  const statusFilter = document.getElementById('status-filter').value;
  const sortBy = document.getElementById('sort-by').value;

  let filtered = allMachines.filter(machine => {
    const matchesSearch = machine.Hostname.toLowerCase().includes(searchText) ||
      (machine.OS?.Caption || '').toLowerCase().includes(searchText);

    const matchesStatus = statusFilter === 'all' || machine.Status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  // Ordenar resultados
  filtered.sort((a, b) => {
    if (sortBy === 'hostname') {
      return a.Hostname.localeCompare(b.Hostname);
    } else if (sortBy === 'status') {
      return a.Status.localeCompare(b.Status);
    } else if (sortBy === 'timestamp') {
      return new Date(b.TimestampUtc) - new Date(a.TimestampUtc);
    }
    return 0;
  });

  renderMachines(filtered);
}

// Função auxiliar para formatar datas
function formatDate(dateString) {
  if (!dateString) return 'N/A';
  try {
    const date = new Date(dateString);
    return isNaN(date.getTime()) ? 'N/A' : date.toLocaleString('pt-BR');
  } catch (e) {
    return 'N/A';
  }
}

function formatDateMS(dateString) {
  if (!dateString) return 'N/A';
  try {
    // Tenta extrair timestamp se for no formato /Date(1234567890123)/
    const match = dateString.match(/\/Date\((\d+)\)\//);
    let timestamp;

    if (match && match[1]) {
      timestamp = parseInt(match[1], 10);
    } else {
      // Se não for formato /Date(...)/, tenta parse direto
      timestamp = Date.parse(dateString);
      if (isNaN(timestamp)) {
        return 'N/A';
      }
    }

    const date = new Date(timestamp);
    return date.toLocaleString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  } catch (e) {
    return 'N/A';
  }
}

// Funções para estados da UI
function showLoading(containerId, message) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `
          <div class="loading">
            <i class="fas fa-spinner fa-spin"></i>
            <p>${message}</p>
          </div>
        `;
  }
}

function showError(containerId, error) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `
          <div class="error">
            <i class="fas fa-exclamation-circle"></i>
            <p>Erro ao carregar dados.</p>
            <p>Verifique se o script PowerShell foi executado e os arquivos JSON foram gerados.</p>
            <p>Detalhes: ${error.message || error}</p>
          </div>
        `;
  }
}

function showEmptyState(containerId, title, message) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `
          <div class="empty-state">
            <i class="fas fa-server"></i>
            <h3>${title}</h3>
            <p>${message}</p>
          </div>
        `;
  }
}

// Alternar tema claro/escuro
function toggleTheme() {
  if (document.body.classList.contains('dark-theme')) {
    document.body.classList.remove('dark-theme');
    localStorage.setItem('theme', 'light');
  } else {
    document.body.classList.add('dark-theme');
    localStorage.setItem('theme', 'dark');
  }
}

// Alternar visualização
function switchView(view) {
  currentView = view;

  // Esconder todas as views
  document.getElementById('dashboard-view').style.display = 'none';
  document.getElementById('machines-view').style.display = 'none';
  document.getElementById('alerts-view').style.display = 'none';

  // Mostrar view selecionada
  document.getElementById(`${view}-view`).style.display = 'block';

  // Atualizar botões
  document.querySelectorAll('.view-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  document.getElementById(`view-${view}`).classList.add('active');

  // Carregar dados específicos da view
  if (view === 'dashboard') {
    updateResourcesChart();
    updateStatusChart();
    updateAlertsChart();
    updateAlertsPanel();
  } else if (view === 'machines') {
    renderMachines(allMachines);
  } else if (view === 'alerts') {
    renderAlertsPanel();
  }
}

// Inicializar eventos
function initEvents() {
  // Botão de tema
  document.getElementById('theme-toggle').addEventListener('click', toggleTheme);

  // Botão de atualizar
  document.getElementById('refresh-btn').addEventListener('click', loadMachinesData);

  // Filtros
  document.getElementById('search-input').addEventListener('input', filterMachines);
  document.getElementById('status-filter').addEventListener('change', filterMachines);
  document.getElementById('sort-by').addEventListener('change', filterMachines);

  // Botões de visualização
  document.getElementById('view-dashboard').addEventListener('click', () => switchView('dashboard'));
  document.getElementById('view-machines').addEventListener('click', () => switchView('machines'));
  document.getElementById('view-alerts').addEventListener('click', () => switchView('alerts'));

  // Botões de exportação
  document.getElementById('export-json').addEventListener('click', exportJSON);
  document.getElementById('export-csv').addEventListener('click', exportCSV);

  // Botões de ação de gráfico
  document.querySelectorAll('.chart-action-btn[data-metric]').forEach(btn => {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.chart-action-btn[data-metric]').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      currentMetric = this.dataset.metric;
      updateResourcesChart();
    });
  });

  document.querySelectorAll('.chart-action-btn[data-chart-type]').forEach(btn => {
    btn.addEventListener('click', function () {
      document.querySelectorAll('.chart-action-btn[data-chart-type]').forEach(b => b.classList.remove('active'));
      this.classList.add('active');
      currentChartType = this.dataset.chartType;
      updateStatusChart();
    });
  });

  // Fechar modal
  document.querySelector('.close-modal').addEventListener('click', () => {
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
  });

  // Fechar modal clicando fora dele
  window.addEventListener('click', (event) => {
    if (event.target === modal) {
      modal.style.display = 'none';
      document.body.style.overflow = 'auto';
    }
  });

  // Tabs de detalhes
  document.addEventListener('click', function (e) {
    if (e.target.classList.contains('tab-btn')) {
      const tabName = e.target.dataset.tab;

      // Remover classe active de todas as tabs e conteúdos
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
      });
      document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
      });

      // Adicionar classe active à tab clicada e seu conteúdo
      e.target.classList.add('active');
      document.getElementById(`tab-${tabName}`).classList.add('active');
    }
  });
}

// Funções de exportação
function exportJSON() {
  const dataStr = JSON.stringify(allMachines, null, 2);
  const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

  const exportFileDefaultName = `inventory-${new Date().toISOString().slice(0, 10)}.json`;

  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', dataUri);
  linkElement.setAttribute('download', exportFileDefaultName);
  linkElement.click();
}

function exportCSV() {
  // Cabeçalhos CSV
  let csvContent = "Hostname,Status,SO,CPU,Memória Total (GB),Memória Livre (GB),Última Atualização\n";

  // Dados
  allMachines.forEach(machine => {
    csvContent += `"${machine.Hostname}",${machine.Status},"${machine.OS?.Caption || 'N/A'}","${machine.CPU?.Name || 'N/A'}",${machine.RAM?.TotalGB || 'N/A'},${machine.RAM?.FreeGB || 'N/A'},"${formatDate(machine.TimestampUtc)}"\n`;
  });

  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", `inventory-${new Date().toISOString().slice(0, 10)}.csv`);
  link.style.visibility = 'hidden';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// Inicializar a aplicação
document.addEventListener('DOMContentLoaded', () => {
  fetchConfig().then((config) => {
    ambienteProducao = config.AMBIENTE_PRODUCAO ? config.AMBIENTE_PRODUCAO : false;
    initEvents();
    loadMachinesData();
  });
});
