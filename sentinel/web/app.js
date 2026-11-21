(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const api = async (url, options = {}) => {
    const response = await fetch(url, { cache: 'no-store', ...options });
    let body;
    try { body = await response.json(); } catch { body = { error: `Respuesta HTTP ${response.status} no válida` }; }
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    return body;
  };
  const jsonPost = (url, data) => api(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  });

  const state = { scanId: null, operationId: null, operationPoll: null, reportReady: false, busy: false, toastTimer: null };

  function toast(message, isError = false) {
    const el = $('toast');
    el.textContent = message;
    el.classList.toggle('error', isError);
    el.classList.add('show');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => el.classList.remove('show'), 4200);
  }
  function pill(id, label, kind) {
    const el = $(id);
    el.textContent = label;
    el.className = `state-pill ${kind}`;
  }
  function setCardText(id, text, kind = '') {
    const el = $(id);
    el.textContent = text;
    el.className = `card-result${kind ? ` ${kind}` : ''}`;
  }
  function esc(text) {
    return String(text ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function timeOnly(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  async function checkHealth() {
    try {
      const data = await api('/api/health');
      $('server-dot').classList.add('online');
      $('server-status').textContent = 'Backend conectado';
      $('version-label').textContent = `v${data.version}`;
      $('footer-version').textContent = data.version;
    } catch (error) {
      $('server-dot').classList.remove('online');
      $('server-status').textContent = 'Backend sin conexión';
      $('version-label').textContent = 'OFFLINE';
      toast(error.message, true);
    }
  }

  $('scope-file').addEventListener('change', async (event) => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.size > 1_000_000) { toast('El archivo supera el límite de 1 MB.', true); return; }
    try {
      const text = await file.text();
      JSON.parse(text);
      $('scope-json').value = text;
      $('file-name').textContent = file.name;
      $('file-name').title = file.name;
      setCardText('scan-result', 'Alcance cargado; será validado por el backend al escanear.', 'positive');
      toast('JSON cargado en la interfaz. La autorización aún debe validarse al iniciar el escaneo.');
    } catch (error) {
      $('file-name').textContent = 'JSON inválido';
      toast(`No se pudo leer el archivo JSON: ${error.message}`, true);
    }
  });

  function renderScan(result) {
    state.scanId = result.scan_id;
    const assets = result.assets || [];
    const rows = [];
    for (const asset of assets) {
      const stateEvidence = (asset.evidence || []).filter(ev => ev.kind === 'port_scan');
      const portStates = new Map();
      for (const ev of stateEvidence) {
        const d = ev.data || {};
        for (const port of d.open || []) portStates.set(port, 'open');
        for (const port of d.closed_or_filtered || []) portStates.set(port, 'closed_or_filtered');
      }
      const serviceByPort = new Map((asset.services || []).map(service => [service.port, service]));
      if (portStates.size === 0) {
        for (const service of asset.services || []) portStates.set(service.port, 'open');
      }
      for (const [port, portState] of [...portStates.entries()].sort((a,b) => a[0] - b[0])) {
        const service = serviceByPort.get(port);
        const name = service ? [service.product, service.version].filter(Boolean).join(' ') || service.banner || 'Servicio TCP observado' : 'Sin servicio TCP observable';
        rows.push(`<tr><td class="mono">${esc(asset.host)}</td><td class="mono">${esc(port)}/tcp</td><td><span class="${service ? 'service-tag' : 'closed-tag'}">${service ? 'ABIERTO' : 'CERRADO / FILTRADO'}</span></td><td>${esc(name)}</td><td>${service && service.http && service.http.status ? esc(`HTTP ${service.http.status}`) : service && service.tls && service.tls.protocol ? esc(service.tls.protocol) : '—'}</td></tr>`);
      }
    }
    $('result-meta').textContent = `${assets.length} ACTIVO(S) · ${result.open_services || 0} SERVICIO(S)`;
    if (!rows.length) {
      $('results-content').innerHTML = `<div class="empty-state"><div class="empty-glyph">⌁</div><strong>Reconocimiento real completado</strong><span>${esc(result.ports_completed)} puerto(s) autorizados revisados; no se observó ningún servicio abierto. Verificá el alcance, las rutas y la disponibilidad del objetivo.</span></div>`;
      return;
    }
    $('results-content').innerHTML = `<div class="table-wrap"><table><thead><tr><th>HOST AUTORIZADO</th><th>PUERTO</th><th>ESTADO</th><th>FINGERPRINT OBSERVADO</th><th>PROTOCOLO</th></tr></thead><tbody>${rows.join('')}</tbody></table></div><p class="micro-label" style="margin:12px 8px 0">${esc(result.ports_completed)} / ${esc(result.ports_total)} PUERTOS · TCP CONNECT · AUDITORÍA ${result.audit_chain && result.audit_chain.ok ? 'ÍNTEGRA' : 'REVISAR'}</p>`;
  }

  function renderActivity(entries) {
    const el = $('activity-list');
    if (!entries || !entries.length) {
      el.innerHTML = '<div class="activity-empty">Sin eventos en esta sesión.</div>';
      return;
    }
    el.innerHTML = entries.map(item => `<div class="activity-item ${esc(item.level || 'info')}"><time class="activity-time">${esc(timeOnly(item.at))}</time><span class="activity-message">${esc(item.message)}</span></div>`).join('');
  }

  async function refreshState() {
    try {
      const data = await api('/api/state');
      renderActivity(data.activity || []);
    } catch { /* health indicator handles an unavailable backend */ }
  }

  function setOperationRunning(message) {
    state.busy = true;
    pill('scan-state', 'EN CURSO', 'running');
    setCardText('scan-result', message || 'Reconocimiento en curso…');
    const button = $('scan-button');
    button.classList.add('cancel');
    button.querySelector('span:first-child').textContent = 'CANCELAR ESCANEO';
    button.querySelector('span:last-child').textContent = '×';
    $('analyze-button').disabled = true;
    $('report-button').disabled = true;
  }
  function finishOperation(op) {
    clearInterval(state.operationPoll);
    state.operationPoll = null;
    state.operationId = null;
    state.busy = false;
    const button = $('scan-button');
    button.disabled = false;
    button.classList.remove('cancel');
    button.querySelector('span:first-child').textContent = 'ESCANEAR';
    button.querySelector('span:last-child').textContent = '↗';
    if (op.status === 'completed' || op.status === 'cancelled') {
      renderScan(op.result || {});
      pill('scan-state', op.status === 'completed' ? 'COMPLETADO' : 'CANCELADO', op.status === 'completed' ? 'done' : 'ready');
      setCardText('scan-result', `${op.result.ports_completed || 0}/${op.result.ports_total || 0} puertos · ${op.result.open_services || 0} servicios observados`, op.status === 'completed' ? 'positive' : 'warning');
      state.scanId = op.result.scan_id || null;
      $('analyze-button').disabled = !state.scanId;
      pill('analyze-state', state.scanId ? 'LISTO' : 'BLOQUEADO', state.scanId ? 'ready' : 'idle');
      if (op.status === 'cancelled') toast('Escaneo cancelado. Los resultados parciales observados se conservan.', true);
      else toast('Reconocimiento terminado. Los resultados vienen del backend Sentinel.');
    } else {
      pill('scan-state', 'ERROR', 'error');
      setCardText('scan-result', op.error || op.message || 'El backend no pudo completar el reconocimiento.', 'warning');
      $('analyze-button').disabled = true;
      toast(op.error || 'Falló el reconocimiento.', true);
    }
    refreshState();
  }

  async function pollOperation(id) {
    try {
      const op = await api(`/api/operations/${encodeURIComponent(id)}`);
      if (op.status === 'queued' || op.status === 'running') {
        setOperationRunning(op.message);
      } else {
        finishOperation(op);
      }
    } catch (error) {
      clearInterval(state.operationPoll);
      state.operationPoll = null;
      state.operationId = null;
      state.busy = false;
      pill('scan-state', 'ERROR', 'error');
      setCardText('scan-result', error.message, 'warning');
      toast(error.message, true);
    }
  }

  $('scan-button').addEventListener('click', async () => {
    if (state.busy && state.operationId) {
      try {
        await api(`/api/cancel/${encodeURIComponent(state.operationId)}`, { method: 'POST' });
        setCardText('scan-result', 'Cancelación solicitada; se espera el fin de la conexión TCP actual (timeout acotado).', 'warning');
        $('scan-button').disabled = true;
      } catch (error) { toast(error.message, true); }
      return;
    }
    let scope;
    try {
      scope = JSON.parse($('scope-json').value);
      if (!scope || typeof scope !== 'object' || Array.isArray(scope)) throw new Error('Se esperaba un objeto JSON de alcance.');
    } catch (error) { toast(`Alcance no válido: ${error.message}`, true); return; }
    $('scan-button').disabled = true;
    pill('scan-state', 'VALIDANDO', 'running');
    setCardText('scan-result', 'El backend está validando autorización y alcance…');
    try {
      const op = await jsonPost('/api/scan', { scope });
      state.operationId = op.id;
      $('scan-button').disabled = false;
      setOperationRunning(op.message);
      state.operationPoll = setInterval(() => pollOperation(op.id), 650);
      pollOperation(op.id);
    } catch (error) {
      $('scan-button').disabled = false;
      pill('scan-state', 'RECHAZADO', 'error');
      setCardText('scan-result', error.message, 'warning');
      toast(error.message, true);
      refreshState();
    }
  });

  $('analyze-button').addEventListener('click', async () => {
    if (!state.scanId || state.busy) return;
    state.busy = true;
    $('analyze-button').disabled = true;
    pill('analyze-state', 'ANALIZANDO', 'running');
    setCardText('analyze-result', 'Ejecutando checks reales sobre servicios observados; no se harán conexiones nuevas…');
    try {
      const result = await jsonPost('/api/analyze', { scan_id: state.scanId });
      const total = result.findings.length;
      pill('analyze-state', 'COMPLETADO', 'done');
      setCardText('analyze-result', `${total} hallazgo(s) · ${result.service_count} servicio(s) observados · 0 conexiones nuevas`, 'positive');
      $('report-button').disabled = false;
      pill('report-state', 'LISTO', 'ready');
      $('analyze-button').disabled = true;
      renderFindings(result);
      toast(`Análisis terminado: ${total} hallazgo(s) derivado(s) de evidencia real.`);
      refreshState();
    } catch (error) {
      pill('analyze-state', 'ERROR', 'error');
      setCardText('analyze-result', error.message, 'warning');
      $('analyze-button').disabled = false;
      toast(error.message, true);
    } finally { state.busy = false; }
  });

  function renderFindings(result) {
    const findings = result.findings || [];
    $('result-meta').textContent = `${findings.length} HALLAZGO(S) · ANÁLISIS OFFLINE`;
    if (!findings.length) {
      $('results-content').innerHTML = '<div class="empty-state"><div class="empty-glyph">✓</div><strong>Sin hallazgos en las observaciones analizadas</strong><span>Esto no certifica ausencia de vulnerabilidades. Revisá los límites de cobertura en el informe técnico.</span></div>';
      return;
    }
    const rows = findings.map(f => `<tr><td class="mono">${esc(f.severity).toUpperCase()}</td><td>${esc(f.title)}</td><td class="mono">${esc(f.asset)}${f.port ? `:${esc(f.port)}` : ''}</td><td>${esc(f.confidence)} / ${esc(f.validation_state)}</td><td class="mono">${f.cvss_score == null ? '—' : esc(f.cvss_score)}</td></tr>`).join('');
    $('results-content').innerHTML = `<div class="table-wrap"><table><thead><tr><th>SEVERIDAD</th><th>HALLAZGO</th><th>ACTIVO</th><th>CONFIANZA / ESTADO</th><th>CVSS</th></tr></thead><tbody>${rows}</tbody></table></div><p class="micro-label" style="margin:12px 8px 0">CRITICAL ${esc(result.severity_counts.critical || 0)} · HIGH ${esc(result.severity_counts.high || 0)} · MEDIUM ${esc(result.severity_counts.medium || 0)} · LOW ${esc(result.severity_counts.low || 0)}</p>`;
  }

  $('report-button').addEventListener('click', async () => {
    if (!state.scanId || state.busy) return;
    state.busy = true;
    $('report-button').disabled = true;
    pill('report-state', 'GENERANDO', 'running');
    setCardText('report-result', 'Generando Markdown, HTML y JSON desde el Assessment analizado…');
    try {
      const result = await jsonPost('/api/report', { scan_id: state.scanId });
      pill('report-state', 'GENERADO', 'done');
      setCardText('report-result', `${result.findings} hallazgo(s) · cadena ${result.audit_chain.ok ? 'consistente internamente' : 'REVISAR'}`, 'positive');
      $('report-id').textContent = result.scan_id;
      $('report-frame').src = `/api/reports/${encodeURIComponent(state.scanId)}/view`;
      $('download-links').innerHTML = ['markdown','html','json'].map(kind => `<a href="/api/reports/${encodeURIComponent(state.scanId)}/${kind}">DESCARGAR ${kind.toUpperCase()} ↓</a>`).join('');
      $('report-panel').hidden = false;
      state.reportReady = true;
      toast('Informe técnico generado por sentinel.report.write_reports.');
      refreshState();
      $('report-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      pill('report-state', 'ERROR', 'error');
      setCardText('report-result', error.message, 'warning');
      $('report-button').disabled = false;
      toast(error.message, true);
    } finally { state.busy = false; }
  });

  checkHealth();
  refreshState();
  setInterval(refreshState, 1600);
  setInterval(checkHealth, 12000);
})();
