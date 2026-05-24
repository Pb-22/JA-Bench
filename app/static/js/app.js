const BUILTIN_THEMES = [
  'night-owl-dark-no-italic',
  'dracula',
  'catppuccin-macchiato',
  'synthwave84',
  'panda',
  'ayu-mirage',
  'kanagawa-wave',
  'kanagawa-dragon',
  'kanagawa-lotus',
  'winter-is-coming',
  'bluloco-light',
  'quiet-light',
];

let currentFlowId = null;
let currentFlowDetail = null;
let currentSearchState = { value: '', type: 'auto' };
let currentViewMode = 'passive';
let latestExport = null;

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function safeJsonParse(value) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return {}; }
}

function stringifySmall(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function applyTheme(themeName) {
  const chosen = BUILTIN_THEMES.includes(themeName) ? themeName : 'night-owl-dark-no-italic';
  document.body.setAttribute('data-theme', chosen);
  try { localStorage.setItem('ja-bench-theme', chosen); } catch {}
  const select = document.getElementById('theme');
  if (select && select.value !== chosen) select.value = chosen;
}

function initializeTheme() {
  let stored = 'night-owl-dark-no-italic';
  try { stored = localStorage.getItem('ja-bench-theme') || stored; } catch {}
  applyTheme(stored);
  document.getElementById('theme')?.addEventListener('change', (event) => applyTheme(event.target.value));
}

function makeBadge(text, tone = 'neutral') {
  return `<span class="pill pill-${tone}">${escapeHtml(text)}</span>`;
}

function toneForProvenance(provenance) {
  const value = (provenance || '').toLowerCase();
  if (value.startsWith('pcap_observed')) return 'success';
  if (value.startsWith('pcap_derived')) return 'accent';
  if (value === 'third_party_enrichment') return 'warning';
  if (value === 'light_active_probe') return 'danger';
  if (value === 'pcap_mimic_active') return 'danger';
  if (value === 'reference_historical') return 'success';
  return 'neutral';
}

function labelForComparisonState(state) {
  const mapping = {
    match: ['match', 'success'],
    mismatch: ['mismatch', 'danger'],
    awaiting_external_value: ['awaiting external', 'neutral'],
    awaiting_local_or_active_value: ['awaiting local/active', 'warning'],
    no_comparison_data: ['no comparison data', 'neutral'],
  };
  return mapping[state] || [state || 'unknown', 'neutral'];
}

function setMatchesPanelOpen(open) {
  const panel = document.getElementById('matches-panel');
  if (panel) panel.open = Boolean(open);
}

function setSearchControls(value, type = 'auto') {
  const valueEl = document.getElementById('reference-search-value');
  const typeEl = document.getElementById('reference-search-type');
  if (valueEl && value !== undefined && value !== null) valueEl.value = value;
  if (typeEl && type) typeEl.value = type;
}

function renderSummary(sample, flowCount, sha256, deduplicated, warnings = []) {
  const summary = document.getElementById('session-summary');
  if (!summary) return;
  const warningLine = warnings.length ? `<li>Parse warnings: ${escapeHtml(warnings.length)}</li>` : '';
  const exportLine = latestExport ? `<li>Latest export: <span class="mono">${escapeHtml(latestExport.filename)}</span></li>` : '';
  summary.innerHTML = `
    <li>Sample: ${escapeHtml(sample.filename || 'n/a')}</li>
    <li>SHA-256: <span class="mono">${escapeHtml(sha256 || 'n/a')}</span></li>
    <li>Conversations: ${escapeHtml(flowCount ?? 'n/a')}</li>
    <li>Packets: ${escapeHtml(sample.packet_count ?? 'n/a')}</li>
    <li>Deduplicated: ${escapeHtml(deduplicated ? 'yes' : 'no')}</li>
    ${warningLine}
    ${exportLine}
  `;
}

function makeFlowHeader(flow) {
  return `
    <section class="flow-section flow-section-hero">
      <div class="flow-title-row">
        <div>
          <div class="section-kicker">selected flow</div>
          <h3 class="flow-title">${escapeHtml(flow.selection_label || flow.flow_key || flow.id || 'flow')}</h3>
        </div>
        <div class="flow-badges">
          ${makeBadge(flow.protocol || 'n/a', (flow.protocol || '').toUpperCase() === 'TLS' ? 'accent' : 'neutral')}
          ${makeBadge(flow.transport || 'n/a', 'neutral')}
        </div>
      </div>
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Packets</span><span class="kv-value">${escapeHtml(flow.packet_count ?? 'n/a')}</span></div>
        <div><span class="kv-label">Bytes</span><span class="kv-value">${escapeHtml(flow.byte_count ?? 'n/a')}</span></div>
        <div><span class="kv-label">Flow key</span><span class="kv-value mono">${escapeHtml(flow.flow_key || 'n/a')}</span></div>
      </div>
    </section>
  `;
}

function presentEntries(entries) {
  return entries.filter(([, value]) => {
    if (value === null || value === undefined) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'object') return Object.keys(value).length > 0;
    return String(value).trim() !== '';
  });
}

function renderPairGrid(entries) {
  const items = presentEntries(entries);
  if (!items.length) return '<div class="compact-note">No populated fields.</div>';
  return `
    <div class="kv-grid compact-grid">
      ${items.map(([label, value]) => `
        <div>
          <span class="kv-label">${escapeHtml(label)}</span>
          <span class="kv-value ${label.toLowerCase().includes('hash') || label.toLowerCase().includes('url') || label.toLowerCase().includes('serial') ? 'mono' : ''}">${escapeHtml(Array.isArray(value) ? value.join(', ') : stringifySmall(value))}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderArtifactConsole(data) {
  const rows = buildArtifactRows(data);
  return `
    <section class="flow-section artifact-console-section">
      <div class="flow-section-header">
        <h4>Derived artifact console</h4>
        ${makeBadge(currentViewMode === 'passive' ? 'passive focus' : currentViewMode === 'light' ? 'light focus' : 'pcap-mimic focus', 'accent')}
      </div>
      <div class="artifact-console">
        ${rows.length ? rows.map((row) => `
          <div class="artifact-row">
            <span class="artifact-key">${escapeHtml(row.key)}</span>
            <span class="artifact-value mono">${escapeHtml(stringifySmall(row.value))}</span>
          </div>
        `).join('') : '<div class="compact-note">No high-signal artifacts derived yet.</div>'}
      </div>
    </section>
  `;
}

function buildArtifactRows(data) {
  const rows = [];
  const fingerprints = data.fingerprints || [];
  const httpPassive = mergeHttpRows((data.http || []).filter((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived'));
  const tlsPassive = (data.tls || []).find((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived');
  const sshPassive = (data.ssh || []).find((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived');
  const passiveCert = (data.certificates || []).find((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived');
  const lightProbe = (data.active_probes || []).find((row) => row.provenance === 'light_active_probe');
  const mimicProbe = (data.active_probes || []).find((row) => row.provenance === 'pcap_mimic_active');
  const shodan = (data.enrichments || []).find((row) => row.provider === 'shodan');

  for (const fp of fingerprints) {
    if (currentViewMode === 'passive' && !String(fp.provenance || '').startsWith('pcap_')) continue;
    if (currentViewMode === 'light' && fp.provenance === 'pcap_mimic_active') continue;
    if (currentViewMode === 'mimic' && fp.provenance === 'light_active_probe' && fp.fingerprint_type !== 'jarm') continue;
    rows.push({ key: `${fp.provenance}.${fp.fingerprint_type}`, value: fp.fingerprint_value });
    const components = safeJsonParse(fp.component_summary_json);
    if (fp.fingerprint_type === 'ja4h') {
      for (const [label, value] of presentEntries([
        ['ja4h.method', components.method],
        ['ja4h.version', components.version],
        ['ja4h.language', components.language],
        ['ja4h.headers', Array.isArray(components.headers) ? components.headers.join(', ') : ''],
        ['ja4h.cookie_fields', Array.isArray(components.cookie_fields) ? components.cookie_fields.join(', ') : ''],
        ['ja4h.referer', components.referer],
      ])) {
        rows.push({ key: label, value });
      }
    }
    if (fp.fingerprint_type === 'ja4s') {
      for (const [label, value] of presentEntries([
        ['ja4s.version', components.version],
        ['ja4s.cipher', components.cipher],
        ['ja4s.alpn', Array.isArray(components.alpn_protocols) ? components.alpn_protocols.join(', ') : ''],
        ['ja4s.extensions', Array.isArray(components.extensions) ? components.extensions.join(', ') : ''],
      ])) {
        rows.push({ key: label, value });
      }
    }
  }

  if (httpPassive) {
    const requestHeaders = safeJsonParse(httpPassive.request_headers_json);
    const responseHeaders = safeJsonParse(httpPassive.response_headers_json);
    const bodySummary = safeJsonParse(httpPassive.response_body_summary_json);
    for (const [label, value] of presentEntries([
      ['http.method', httpPassive.request_method],
      ['http.version', bodySummary.http_version],
      ['http.host', httpPassive.host],
      ['http.uri', httpPassive.uri],
      ['http.full_url', httpPassive.full_url],
      ['http.user_agent', httpPassive.user_agent],
      ['http.accept', requestHeaders['accept']],
      ['http.accept_language', requestHeaders['accept-language']],
      ['http.accept_encoding', requestHeaders['accept-encoding']],
      ['http.referer', requestHeaders['referer']],
      ['http.cookie', requestHeaders['cookie']],
      ['http.status', httpPassive.status_code],
      ['http.content_type', responseHeaders['content-type']],
      ['http.location', httpPassive.location_header],
      ['http.server', responseHeaders['server']],
    ])) {
      rows.push({ key: label, value });
    }
  }

  if (tlsPassive) {
    const alpn = safeJsonParse(tlsPassive.alpn_json);
    for (const [label, value] of presentEntries([
      ['tls.sni', tlsPassive.sni],
      ['tls.version', tlsPassive.tls_version_negotiated || tlsPassive.tls_version_offered],
      ['tls.alpn', Array.isArray(alpn) ? alpn.join(', ') : ''],
      ['tls.selected_cipher', tlsPassive.selected_cipher],
    ])) {
      rows.push({ key: label, value });
    }
  }

  if (sshPassive) {
    const kexAlgorithms = safeJsonParse(sshPassive.kex_algorithms_json);
    for (const [label, value] of presentEntries([
      ['ssh.protocol', sshPassive.protocol_banner_client || sshPassive.protocol_banner_server],
      ['ssh.client_algorithms', kexAlgorithms.client],
      ['ssh.server_algorithms', kexAlgorithms.server],
    ])) {
      rows.push({ key: label, value });
    }
  }

  if (passiveCert) {
    for (const [label, value] of presentEntries([
      ['cert.subject', passiveCert.subject_dn],
      ['cert.issuer', passiveCert.issuer_dn],
      ['cert.serial', passiveCert.serial_number],
      ['cert.leaf_sha256', passiveCert.leaf_sha256],
      ['cert.spki_sha256', passiveCert.spki_sha256],
    ])) {
      rows.push({ key: label, value });
    }
  }

  if (currentViewMode !== 'passive' && lightProbe) {
    const responseSummary = safeJsonParse(lightProbe.response_summary_json);
    if (lightProbe.probe_type === 'jarm') rows.push({ key: 'light_active_probe.jarm', value: responseSummary.result });
    if (lightProbe.probe_type === 'http_metadata') rows.push({ key: 'light_active_probe.http_status', value: responseSummary.status_line });
  }

  if (currentViewMode === 'mimic' && mimicProbe) {
    const responseSummary = safeJsonParse(mimicProbe.response_summary_json);
    rows.push({ key: 'pcap_mimic_active.http_status', value: responseSummary.status_line });
  }

  if (currentViewMode !== 'passive' && shodan) {
    const summary = safeJsonParse(shodan.result_summary_json);
    for (const [label, value] of presentEntries([
      ['shodan.jarm', summary.jarm],
      ['shodan.ja3s', summary.ja3s],
      ['shodan.cert_subject', summary.cert_subject],
      ['shodan.ports', Array.isArray(summary.ports) ? summary.ports.join(', ') : ''],
    ])) {
      rows.push({ key: label, value });
    }
  }

  return rows;
}

function mergeHttpRows(rows) {
  if (!rows.length) return null;
  const merged = { ...rows[0] };
  const requestHeaders = {};
  const responseHeaders = {};
  const bodySummary = {};
  for (const row of rows) {
    for (const field of ['request_method', 'host', 'uri', 'full_url', 'query_string', 'user_agent', 'referer', 'status_code', 'location_header', 'observed_at']) {
      if ((merged[field] === null || merged[field] === undefined || merged[field] === '') && row[field] !== null && row[field] !== undefined && row[field] !== '') {
        merged[field] = row[field];
      }
    }
    Object.assign(requestHeaders, safeJsonParse(row.request_headers_json));
    Object.assign(responseHeaders, safeJsonParse(row.response_headers_json));
    Object.assign(bodySummary, safeJsonParse(row.response_body_summary_json));
  }
  merged.request_headers_json = Object.keys(requestHeaders).length ? requestHeaders : null;
  merged.response_headers_json = Object.keys(responseHeaders).length ? responseHeaders : null;
  merged.response_body_summary_json = Object.keys(bodySummary).length ? bodySummary : null;
  return merged;
}

function renderHttpRow(row) {
  const requestHeaders = safeJsonParse(row.request_headers_json);
  const responseHeaders = safeJsonParse(row.response_headers_json);
  const bodySummary = safeJsonParse(row.response_body_summary_json);
  const method = row.request_method || 'HTTP';
  const target = row.full_url || row.uri || '/';
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title mono">${escapeHtml(`${method} ${target}`)}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      ${renderPairGrid([
        ['Host', row.host],
        ['Version', bodySummary.http_version],
        ['Status', row.status_code],
        ['Reason', bodySummary.response_phrase],
        ['User-Agent', row.user_agent],
        ['Accept', requestHeaders['accept']],
        ['Accept-Language', requestHeaders['accept-language']],
        ['Accept-Encoding', requestHeaders['accept-encoding']],
        ['Referer', requestHeaders['referer']],
        ['Cookie', requestHeaders['cookie']],
        ['Connection', requestHeaders['connection']],
        ['Authorization', requestHeaders['authorization']],
        ['Cache-Control', requestHeaders['cache-control']],
        ['Content-Type', responseHeaders['content-type']],
        ['Content-Length', responseHeaders['content-length']],
        ['Location', row.location_header],
        ['Server', responseHeaders['server']],
      ])}
    </article>
  `;
}

function renderHttpBucket(title, rows, note) {
  if (!rows.length) return '';
  return `
    <section class="flow-section">
      <div class="flow-section-header">
        <h4>${escapeHtml(title)}</h4>
        <span class="compact-note">${escapeHtml(note)}</span>
      </div>
      <div class="stack-list">${rows.slice(0, 4).map(renderHttpRow).join('')}</div>
    </section>
  `;
}

function formatHttpShape(row) {
  if (!row) return 'n/a';
  return `${row.method || 'HTTP'} ${row.full_url || row.uri || '/'} | ${row.status_code || 'n/a'} | ${row.content_type || 'n/a'}`;
}

function renderSingleHttpComparison(title, summary, passiveRow, candidateRow) {
  if (!summary) return '';
  const [label, tone] = {
    match: ['match', 'success'],
    changed: ['changed', 'warning'],
    awaiting_candidate: ['awaiting active row', 'neutral'],
    no_passive_baseline: ['no passive baseline', 'neutral'],
    no_data: ['no data', 'neutral'],
  }[summary.state] || [summary.state || 'unknown', 'neutral'];
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(title)}</div>
        ${makeBadge(label, tone)}
      </div>
      <div class="comparison-columns">
        <div>
          <div class="kv-label">Passive</div>
          <div class="mono comparison-shape">${escapeHtml(formatHttpShape(passiveRow))}</div>
        </div>
        <div>
          <div class="kv-label">Active</div>
          <div class="mono comparison-shape">${escapeHtml(formatHttpShape(candidateRow))}</div>
        </div>
      </div>
      ${summary.changed_fields && summary.changed_fields.length ? `<div class="diff-list top-gap">${summary.changed_fields.map((item) => `<div class="diff-row"><span class="pill pill-warning">${escapeHtml(item.field)}</span><span class="diff-before mono">${escapeHtml(stringifySmall(item.passive))}</span><span class="diff-arrow">→</span><span class="diff-after mono">${escapeHtml(stringifySmall(item.candidate))}</span></div>`).join('')}</div>` : ''}
      ${summary.same_fields && summary.same_fields.length ? `<div class="inline-note top-gap"><span class="kv-label">Same</span><span class="kv-value">${escapeHtml(summary.same_fields.join(', '))}</span></div>` : ''}
    </article>
  `;
}

function renderHttpSections(rows, comparison) {
  const passive = mergeHttpRows(rows.filter((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived'));
  const light = mergeHttpRows(rows.filter((row) => row.provenance === 'light_active_probe'));
  const mimic = mergeHttpRows(rows.filter((row) => row.provenance === 'pcap_mimic_active'));
  const sections = [];
  if (passive) sections.push(renderHttpBucket('Passive HTTP observations', [passive], 'Observed in the PCAP.'));
  if (currentViewMode === 'light' && light) sections.push(renderHttpBucket('Light-tested HTTP observations', [light], 'Bounded metadata fetches performed after ingest.'));
  if (currentViewMode === 'mimic' && mimic) sections.push(renderHttpBucket('PCAP-Mimic HTTP observations', [mimic], 'Bounded request-shape replay based on the PCAP.'));

  if (currentViewMode === 'light' && comparison?.light_vs_passive) {
    sections.push(`
      <section class="flow-section">
        <div class="flow-section-header">
          <h4>HTTP comparison</h4>
          ${makeBadge('passive vs active', 'accent')}
        </div>
        <div class="stack-list">
          ${renderSingleHttpComparison('Light Testing vs passive', comparison.light_vs_passive, comparison.passive, comparison.light)}
        </div>
      </section>
    `);
  }

  if (currentViewMode === 'mimic' && comparison?.mimic_vs_passive) {
    sections.push(`
      <section class="flow-section">
        <div class="flow-section-header">
          <h4>HTTP comparison</h4>
          ${makeBadge('passive vs mimic', 'accent')}
        </div>
        <div class="stack-list">
          ${renderSingleHttpComparison('PCAP-Mimic vs passive', comparison.mimic_vs_passive, comparison.passive, comparison.mimic)}
        </div>
      </section>
    `);
  }

  return sections.join('');
}

function renderTlsRow(row) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title mono">${escapeHtml(row.tls_role || 'TLS observation')}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      ${renderPairGrid([
        ['Role', row.tls_role],
        ['Version', row.tls_version_offered || row.tls_version_negotiated],
        ['SNI', row.sni],
        ['ALPN', Array.isArray(safeJsonParse(row.alpn_json)) ? safeJsonParse(row.alpn_json).join(', ') : ''],
        ['Cipher', row.selected_cipher],
      ])}
    </article>
  `;
}

function renderSshRow(row) {
  const kexAlgorithms = safeJsonParse(row.kex_algorithms_json);
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title mono">SSH observation</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      ${renderPairGrid([
        ['Protocol', row.protocol_banner_client || row.protocol_banner_server],
        ['Client algorithms', kexAlgorithms.client],
        ['Server algorithms', kexAlgorithms.server],
      ])}
    </article>
  `;
}

function renderCertRow(cert) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(cert.subject_dn || 'certificate')}</div>
        ${makeBadge(cert.provenance || 'unknown', toneForProvenance(cert.provenance))}
      </div>
      ${renderPairGrid([
        ['Issuer', cert.issuer_dn],
        ['Serial', cert.serial_number],
        ['SAN', safeJsonParse(cert.san_json)],
        ['Leaf SHA-256', cert.leaf_sha256],
        ['SPKI SHA-256', cert.spki_sha256],
        ['Chain position', cert.chain_position],
      ])}
    </article>
  `;
}

function renderProbeSummary(probeType, requestSummary, responseSummary) {
  if (probeType === 'jarm') {
    return renderPairGrid([
      ['JARM', responseSummary.result],
      ['Command', (requestSummary.command || []).join(' ')],
    ]);
  }
  if (probeType === 'tls_cert_grab') {
    const cert = responseSummary.certificate || {};
    return renderPairGrid([
      ['Subject', cert.subject_dn],
      ['Issuer', cert.issuer_dn],
      ['Leaf SHA-256', cert.leaf_sha256],
      ['Server name', responseSummary.server_name || requestSummary.server_name],
    ]);
  }
  return renderPairGrid([
    ['Method', requestSummary.method],
    ['URL', requestSummary.url],
    ['HTTP', responseSummary.status_line],
    ['Content-Type', responseSummary.content_type],
    ['Location', responseSummary.location],
    ['Preview', responseSummary.body_preview_utf8],
  ]);
}

function renderActiveProbeRow(row) {
  const requestSummary = safeJsonParse(row.request_summary_json);
  const responseSummary = safeJsonParse(row.response_summary_json);
  const probeLabel = {
    jarm: 'Light JARM',
    tls_cert_grab: 'TLS cert grab',
    http_metadata: 'HTTP metadata',
    pcap_mimic_request: 'PCAP-Mimic request',
  }[row.probe_type] || row.probe_type || 'probe';
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(probeLabel)} ${escapeHtml(row.target_host || '')}:${escapeHtml(row.target_port || '')}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      ${renderPairGrid([
        ['Status', row.status],
        ['Started', row.started_at],
        ['Completed', row.completed_at],
      ])}
      <div class="top-gap">${renderProbeSummary(row.probe_type, requestSummary, responseSummary)}</div>
    </article>
  `;
}

function renderEnrichmentRow(row) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(row.provider || 'provider')} → ${escapeHtml(row.target_value || 'target')}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      ${renderPairGrid([
        ['Target type', row.target_type],
        ['Query', row.provider_query],
        ['Summary', row.result_summary_json],
      ])}
    </article>
  `;
}

function makeObservationList(title, rows, renderer) {
  if (!rows.length) return '';
  return `
    <section class="flow-section">
      <div class="flow-section-header">
        <h4>${escapeHtml(title)}</h4>
        ${makeBadge(rows[0].provenance || 'unknown', toneForProvenance(rows[0].provenance))}
      </div>
      <div class="stack-list">${rows.map(renderer).join('')}</div>
    </section>
  `;
}

function renderFingerprintBreakdown(fingerprints, referenceMatches, shodanQueries, comparisonSummary) {
  if (!fingerprints.length) return 'No stored fingerprints yet for this flow.';
  const highSignalTypes = ['ja4h', 'ja4', 'ja4s', 'ja3', 'ja3s', 'jarm', 'hassh'];
  const sorted = [...fingerprints].sort((left, right) => {
    const a = highSignalTypes.indexOf(left.fingerprint_type);
    const b = highSignalTypes.indexOf(right.fingerprint_type);
    return (a === -1 ? 99 : a) - (b === -1 ? 99 : b);
  });
  return `<div class="stack-list">${sorted.map((fp) => {
    const key = `${fp.fingerprint_type}:${fp.fingerprint_value}`;
    const matchCount = (referenceMatches[key] || []).length;
    const comparison = comparisonSummary[fp.fingerprint_type] || null;
    const [comparisonLabel, comparisonTone] = labelForComparisonState(comparison?.state);
    return `
      <article class="data-card">
        <div class="flow-section-header">
          <div class="data-card-title mono">${escapeHtml(fp.fingerprint_type)}${fp.role && fp.role !== 'unknown' ? ` (${escapeHtml(fp.role)})` : ''}</div>
          <div class="flow-badges">
            ${makeBadge(fp.provenance || 'unknown', toneForProvenance(fp.provenance))}
            ${matchCount ? makeBadge(`${matchCount} reference match${matchCount === 1 ? '' : 'es'}`, 'success') : ''}
            ${comparison ? makeBadge(comparisonLabel, comparisonTone) : ''}
          </div>
        </div>
        <div class="mono fingerprint-value">${escapeHtml(fp.fingerprint_value)}</div>
        <div class="panel-actions top-gap">
          <button type="button" class="fingerprint-search-button" data-search-type="${escapeHtml(fp.fingerprint_type || 'auto')}" data-search-value="${escapeHtml(fp.fingerprint_value || '')}">Lookup</button>
        </div>
        ${shodanQueries[key] ? `<div class="inline-note"><span class="kv-label">Shodan</span><span class="mono">${escapeHtml(shodanQueries[key])}</span></div>` : ''}
      </article>
    `;
  }).join('')}</div>`;
}

function renderAssessments(fingerprints, referenceMatches, shodanQueries, certRows, comparisonSummary, httpComparison) {
  if (!fingerprints.length && !certRows.length && !httpComparison?.light_vs_passive && !httpComparison?.mimic_vs_passive) return 'No fingerprint-derived assessments yet.';
  const items = [];
  if (certRows.length) items.push(`<li><strong>Certificate coverage:</strong> ${escapeHtml(certRows.length)} stored certificate row(s).</li>`);
  for (const fp of fingerprints) {
    const key = `${fp.fingerprint_type}:${fp.fingerprint_value}`;
    const matchCount = (referenceMatches[key] || []).length;
    const comparison = comparisonSummary[fp.fingerprint_type] || null;
    items.push(`<li><strong>${escapeHtml(fp.fingerprint_type)}:</strong> ${matchCount ? `${escapeHtml(matchCount)} bundled historical reference match(es).` : 'no bundled historical reference match yet.'}</li>`);
    if (shodanQueries[key]) items.push(`<li><strong>Shodan candidate:</strong> <span class="mono">${escapeHtml(shodanQueries[key])}</span></li>`);
    if (comparison) items.push(`<li><strong>${escapeHtml(fp.fingerprint_type)} comparison:</strong> ${escapeHtml(comparison.state)}.</li>`);
  }
  if (httpComparison?.light_vs_passive && currentViewMode === 'light') items.push(`<li><strong>HTTP Light Testing:</strong> ${escapeHtml(httpComparison.light_vs_passive.notes || httpComparison.light_vs_passive.state)}.</li>`);
  if (httpComparison?.mimic_vs_passive && currentViewMode === 'mimic') items.push(`<li><strong>HTTP PCAP-Mimic:</strong> ${escapeHtml(httpComparison.mimic_vs_passive.notes || httpComparison.mimic_vs_passive.state)}.</li>`);
  items.push('<li><strong>Provenance:</strong> rows are labeled as <span class="mono">pcap_observed</span>, <span class="mono">pcap_derived</span>, <span class="mono">light_active_probe</span>, <span class="mono">third_party_enrichment</span>, or <span class="mono">pcap_mimic_active</span>.</li>');
  return `<ul class="analysis-list">${items.join('')}</ul>`;
}

function renderStructuredDetail(detail) {
  const preferredOrder = ['flow_id', 'filename', 'application', 'os_name', 'device_name', 'library_name', 'user_agent_string', 'certificate_authority', 'ja4s_fingerprint', 'ja4h_fingerprint', 'ja4x_fingerprint', 'ja4t_fingerprint', 'confidence_note', 'src_ip', 'dst_ip', 'protocol', 'subject_dn', 'issuer_dn'];
  const entries = Object.entries(detail || {}).filter(([, value]) => value !== null && value !== undefined && value !== '');
  entries.sort((left, right) => {
    const a = preferredOrder.indexOf(left[0]);
    const b = preferredOrder.indexOf(right[0]);
    return (a === -1 ? 99 : a) - (b === -1 ? 99 : b) || left[0].localeCompare(right[0]);
  });
  if (!entries.length) return '<div class="compact-note">No structured detail.</div>';
  return `<div class="detail-list">${entries.map(([key, value]) => `
    <div class="detail-row">
      <span class="detail-key">${escapeHtml(key)}</span>
      <span class="detail-value mono">${escapeHtml(Array.isArray(value) ? value.join(', ') : stringifySmall(value))}</span>
    </div>
  `).join('')}</div>`;
}

function renderSearchResults(result) {
  const matches = result?.matches || [];
  if (!matches.length) return 'No local match found.';
  const counts = result?.category_counts || {};
  const countChips = Object.entries(counts).map(([key, count]) => makeBadge(`${key}: ${count}`, key.startsWith('reference') ? 'success' : 'neutral')).join(' ');
  return `<div class="stack-list">
    <article class="data-card search-summary-card">
      <div class="flow-section-header">
        <div class="data-card-title">Search summary</div>
        ${makeBadge(`${matches.length} match${matches.length === 1 ? '' : 'es'}`, 'accent')}
      </div>
      <div class="flow-badges top-gap">${countChips}</div>
    </article>
    ${matches.map((match) => `
      <article class="data-card">
        <div class="flow-section-header">
          <div class="data-card-title mono">${escapeHtml(match.title || 'match')}</div>
          ${makeBadge(match.provenance || match.match_type || 'unknown', toneForProvenance(match.provenance || 'neutral'))}
        </div>
        ${renderPairGrid([
          ['Type', match.match_type],
          ['Context', match.subtitle],
        ])}
        <div class="top-gap">${renderStructuredDetail(match.detail || {})}</div>
        ${match.detail?.flow_id ? `<div class="panel-actions top-gap"><button type="button" class="flow-jump-button" data-flow-id="${escapeHtml(match.detail.flow_id)}">Open flow ${escapeHtml(match.detail.flow_id)}</button></div>` : ''}
      </article>
    `).join('')}
  </div>`;
}

function renderModeFilteredSections(data) {
  const passiveCerts = (data.certificates || []).filter((row) => row.provenance === 'pcap_observed' || row.provenance === 'pcap_derived');
  const lightProbes = (data.active_probes || []).filter((row) => row.provenance === 'light_active_probe');
  const mimicProbes = (data.active_probes || []).filter((row) => row.provenance === 'pcap_mimic_active');
  const enrichments = currentViewMode === 'passive' ? [] : (data.enrichments || []);

  const sections = [
    renderArtifactConsole(data),
    renderHttpSections(data.http || [], data.http_comparison || {}),
    makeObservationList('TLS observations', (data.tls || []).slice(0, 5), renderTlsRow),
    makeObservationList('SSH observations', (data.ssh || []).slice(0, 5), renderSshRow),
    makeObservationList('Certificates', passiveCerts.slice(0, 4), renderCertRow),
  ];

  if (currentViewMode === 'light') {
    sections.push(makeObservationList('Light-testing probes', lightProbes.slice(0, 6), renderActiveProbeRow));
  }
  if (currentViewMode === 'mimic') {
    sections.push(makeObservationList('PCAP-Mimic probes', mimicProbes.slice(0, 6), renderActiveProbeRow));
  }
  if (enrichments.length) {
    sections.push(makeObservationList('Enrichments', enrichments.slice(0, 4), renderEnrichmentRow));
  }

  return sections.join('');
}

function renderFlowDetail(data) {
  return {
    mainHtml: `<div class="flow-report">${makeFlowHeader(data.flow || {})}${renderModeFilteredSections(data)}</div>`,
    breakdownHtml: renderFingerprintBreakdown(data.fingerprints || [], data.reference_matches || {}, data.shodan_queries || {}, data.comparison_summary || {}),
    assessmentsHtml: renderAssessments(data.fingerprints || [], data.reference_matches || {}, data.shodan_queries || {}, data.certificates || [], data.comparison_summary || {}, data.http_comparison || {}),
    logText: `Loaded flow detail for flow ${data.flow?.id || 'n/a'}. HTTP rows=${(data.http || []).length}, TLS rows=${(data.tls || []).length}, SSH rows=${(data.ssh || []).length}, certs=${(data.certificates || []).length}, active probes=${(data.active_probes || []).length}, fingerprints=${(data.fingerprints || []).length}, enrichments=${(data.enrichments || []).length}`,
  };
}

function paintCurrentFlowDetail() {
  if (!currentFlowDetail) return;
  const mainOutput = document.getElementById('main-output');
  const breakdown = document.getElementById('ja-breakdown');
  const assessments = document.getElementById('indicator-assessments');
  const logBox = document.getElementById('log-box');
  const rendered = renderFlowDetail(currentFlowDetail);
  if (mainOutput) mainOutput.innerHTML = rendered.mainHtml;
  if (breakdown) breakdown.innerHTML = rendered.breakdownHtml;
  if (assessments) assessments.innerHTML = rendered.assessmentsHtml;
  if (logBox) logBox.textContent = rendered.logText;
}

async function runReferenceLookup() {
  const valueEl = document.getElementById('reference-search-value');
  const typeEl = document.getElementById('reference-search-type');
  const resultsEl = document.getElementById('reference-search-results');
  if (!valueEl || !typeEl || !resultsEl) return;
  const value = valueEl.value.trim();
  const type = typeEl.value.trim();
  if (!value) {
    resultsEl.textContent = 'Enter a value to search.';
    return;
  }
  currentSearchState = { value, type };
  resultsEl.textContent = 'Searching local data...';
  setMatchesPanelOpen(true);
  try {
    const params = new URLSearchParams({ value, type });
    const resp = await fetch(`/api/reference-search?${params.toString()}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Search failed');
    resultsEl.innerHTML = renderSearchResults(data);
  } catch (err) {
    resultsEl.textContent = `Search failed: ${err}`;
  }
}

async function loadFlowDetail(flowId) {
  const logBox = document.getElementById('log-box');
  if (!flowId) return;
  try {
    const resp = await fetch(`/api/flows/${flowId}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Flow detail lookup failed');
    currentFlowId = Number(flowId);
    currentFlowDetail = data;
    paintCurrentFlowDetail();
  } catch (err) {
    if (logBox) logBox.textContent = `Flow detail load failed: ${err}`;
  }
}

async function postFlowAction(path, startText, doneBuilder) {
  const logBox = document.getElementById('log-box');
  if (!currentFlowId) {
    if (logBox) logBox.textContent = 'Select a flow first.';
    return;
  }
  if (logBox) logBox.textContent = `${startText} for flow ${currentFlowId}...`;
  try {
    const resp = await fetch(`/api/flows/${currentFlowId}/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ force_refresh: false }),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Action failed');
    if (logBox) logBox.textContent = doneBuilder(data);
    await loadFlowDetail(currentFlowId);
  } catch (err) {
    if (logBox) logBox.textContent = `${startText} failed: ${err}`;
  }
}

function runLightJarm() {
  return postFlowAction('probe/jarm', 'Running Light JARM', (data) => `Light JARM complete for flow ${currentFlowId}. Target=${data.target_host}:${data.target_port}, JARM=${data.fingerprint_value}`);
}

function runLightCert() {
  return postFlowAction('probe/tls-cert', 'Running TLS cert grab', (data) => `TLS cert grab complete for flow ${currentFlowId}. Subject=${data.certificate?.subject_dn || 'n/a'}`);
}

function runLightHttp() {
  return postFlowAction('probe/http-metadata', 'Running HTTP metadata probe', (data) => `HTTP metadata probe complete for flow ${currentFlowId}. URL=${data.target_url}, status=${data.response_summary?.status_line || 'n/a'}`);
}

function runPcapMimic() {
  return postFlowAction('probe/pcap-mimic', 'Running PCAP-Mimic request', (data) => `PCAP-Mimic request complete for flow ${currentFlowId}. URL=${data.target_url}, status=${data.response_summary?.status_line || 'n/a'}`);
}

function runShodanEnrichment() {
  return postFlowAction('enrich/shodan', 'Running opt-in Shodan enrichment', (data) => `Shodan enrichment complete for flow ${currentFlowId}. Service IP=${data.service_ip}, passive JARM=${data.host_lookup?.jarm || 'n/a'}, passive JA3S=${data.host_lookup?.ja3s || 'n/a'}`);
}

async function runExport() {
  const scopeEl = document.getElementById('scope');
  const formatEl = document.getElementById('format');
  const logBox = document.getElementById('log-box');
  if (!scopeEl || !formatEl) return;
  const scopeMap = { 'Selected Conversation': 'selected_conversation', 'Search Results': 'search_results', 'All': 'all' };
  const payload = {
    scope: scopeMap[scopeEl.value] || 'selected_conversation',
    format: (formatEl.value || 'JSON').toLowerCase(),
    flow_id: currentFlowId,
    search_value: currentSearchState.value,
    search_type: currentSearchState.type,
  };
  if (logBox) logBox.textContent = `Building ${payload.format.toUpperCase()} export for ${scopeEl.value}...`;
  try {
    const resp = await fetch('/api/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Export failed');
    latestExport = data;
    if (logBox) logBox.innerHTML = `Export ready: <span class="mono">${escapeHtml(data.filename)}</span> <a href="${escapeHtml(data.download_url)}">download</a>`;
    renderSummary({ filename: currentFlowDetail?.flow?.selection_label || 'selected flow' }, null, null, false, []);
    if (data.download_url) {
      const link = document.createElement('a');
      link.href = data.download_url;
      link.download = data.filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
    }
  } catch (err) {
    if (logBox) logBox.textContent = `Export failed: ${err}`;
  }
}

async function uploadPcap() {
  const fileInput = document.getElementById('pcap-file');
  const fileNameEl = document.getElementById('pcap-file-name');
  const mainOutput = document.getElementById('main-output');
  const logBox = document.getElementById('log-box');
  const selector = document.getElementById('conversation-selector');
  if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
    if (logBox) logBox.textContent = 'Select a PCAP first.';
    return;
  }
  const file = fileInput.files[0];
  if (fileNameEl) fileNameEl.value = file.name;
  if (mainOutput) mainOutput.innerHTML = `<div class="loading-note">Uploading and parsing <span class="mono">${escapeHtml(file.name)}</span>...</div>`;
  if (logBox) logBox.textContent = 'Running upload + parse...';
  const formData = new FormData();
  formData.append('pcap', file);
  try {
    const resp = await fetch('/api/upload-pcap', { method: 'POST', body: formData });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Upload failed');
    currentFlowDetail = null;
    setMatchesPanelOpen(false);
    document.getElementById('reference-search-results').textContent = 'No search results yet.';
    setSearchControls('', 'auto');
    if (selector) {
      selector.innerHTML = '';
      const flows = data.flows || [];
      if (!flows.length) {
        const opt = document.createElement('option');
        opt.textContent = 'No flows found';
        selector.appendChild(opt);
        selector.disabled = true;
      } else {
        for (const flow of flows) {
          const opt = document.createElement('option');
          opt.value = String(flow.id || flow.flow_key);
          opt.textContent = flow.selection_label || flow.flow_key;
          selector.appendChild(opt);
        }
        selector.disabled = false;
        selector.selectedIndex = 0;
      }
    }
    renderSummary(data.sample || {}, (data.flows || []).length, data.sha256, data.deduplicated, data.parse_warnings || []);
    if (logBox) {
      const warningTail = (data.parse_warnings || []).length ? ` Parse warnings: ${data.parse_warnings.length}.` : '';
      logBox.textContent = `${data.deduplicated ? 'Duplicate PCAP detected by SHA-256. Reused existing stored sample and flows.' : 'PCAP uploaded, hashed, stored, parsed, and passive artifact extraction completed.'}${warningTail}`;
    }
    if (data.flows && data.flows.length > 0) {
      currentFlowId = Number(data.flows[0].id || 0);
      await loadFlowDetail(currentFlowId);
    }
  } catch (err) {
    if (mainOutput) mainOutput.innerHTML = `<div class="error-note">Upload failed: ${escapeHtml(err)}</div>`;
    if (logBox) logBox.textContent = `Upload failed: ${err}`;
  }
}

function handleModeChange(event) {
  currentViewMode = event.target.value || 'passive';
  paintCurrentFlowDetail();
}

document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  document.getElementById('reference-search-button')?.addEventListener('click', runReferenceLookup);
  document.getElementById('light-jarm-button')?.addEventListener('click', runLightJarm);
  document.getElementById('light-cert-button')?.addEventListener('click', runLightCert);
  document.getElementById('light-http-button')?.addEventListener('click', runLightHttp);
  document.getElementById('pcap-mimic-button')?.addEventListener('click', runPcapMimic);
  document.getElementById('shodan-enrich-button')?.addEventListener('click', runShodanEnrichment);
  document.getElementById('export-button')?.addEventListener('click', runExport);
  document.querySelectorAll('input[name="view-mode"]').forEach((el) => el.addEventListener('change', handleModeChange));

  const fileInput = document.getElementById('pcap-file');
  const fileNameEl = document.getElementById('pcap-file-name');
  if (fileInput && fileNameEl) {
    fileInput.addEventListener('change', () => {
      fileNameEl.value = fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'No file selected';
    });
  }

  document.getElementById('read-pcap-button')?.addEventListener('click', uploadPcap);

  const selector = document.getElementById('conversation-selector');
  if (selector) {
    selector.addEventListener('change', async () => {
      if (selector.value) await loadFlowDetail(selector.value);
    });
  }

  document.getElementById('reference-search-results')?.addEventListener('click', async (event) => {
    const button = event.target.closest('.flow-jump-button');
    if (!button) return;
    const flowId = Number(button.dataset.flowId || 0);
    if (!flowId) return;
    if (selector) selector.value = String(flowId);
    await loadFlowDetail(flowId);
  });

  document.getElementById('ja-breakdown')?.addEventListener('click', async (event) => {
    const button = event.target.closest('.fingerprint-search-button');
    if (!button) return;
    setSearchControls(button.dataset.searchValue || '', button.dataset.searchType || 'auto');
    await runReferenceLookup();
  });
});
