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
let currentSearchState = { value: '', type: 'auto' };
let latestExport = null;

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
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
  const select = document.getElementById('theme');
  if (select) select.addEventListener('change', () => applyTheme(select.value));
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

function setSearchControls(value, type) {
  const ids = [['reference-search-value', value], ['quick-search-value', value], ['reference-search-type', type], ['quick-search-type', type]];
  for (const [id, v] of ids) {
    const el = document.getElementById(id);
    if (el && v !== undefined && v !== null) el.value = v;
  }
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

function renderHttpRow(row) {
  const responseBody = safeJsonParse(row.response_body_summary_json);
  const responseHeaders = safeJsonParse(row.response_headers_json);
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title mono">${escapeHtml(row.request_method || 'HTTP')} ${escapeHtml(row.full_url || row.uri || '/')}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Host</span><span class="kv-value">${escapeHtml(row.host || 'n/a')}</span></div>
        <div><span class="kv-label">Status</span><span class="kv-value">${escapeHtml(row.status_code || 'n/a')}</span></div>
        <div><span class="kv-label">User-Agent</span><span class="kv-value">${escapeHtml(row.user_agent || 'n/a')}</span></div>
        <div><span class="kv-label">Content-Type</span><span class="kv-value">${escapeHtml(responseHeaders['content-type'] || responseHeaders['Content-Type'] || 'n/a')}</span></div>
        <div><span class="kv-label">Location</span><span class="kv-value mono">${escapeHtml(row.location_header || 'n/a')}</span></div>
        <div><span class="kv-label">Preview</span><span class="kv-value mono">${escapeHtml(responseBody.body_preview_utf8 || 'n/a')}</span></div>
      </div>
    </article>
  `;
}

function renderHttpSections(rows, comparison) {
  if (!rows.length && !comparison) return '';
  const passive = rows.filter((row) => ['pcap_observed', 'pcap_derived'].includes(row.provenance));
  const light = rows.filter((row) => row.provenance === 'light_active_probe');
  const mimic = rows.filter((row) => row.provenance === 'pcap_mimic_active');
  return `
    ${renderHttpBucket('Passive HTTP observations', passive, 'Observed in the PCAP.')}
    ${renderHttpBucket('Light-tested HTTP observations', light, 'Bounded metadata fetches performed after ingest.')}
    ${renderHttpBucket('PCAP-Mimic HTTP observations', mimic, 'Bounded request-shape replay based on the PCAP.')}
    ${renderHttpComparisonSection(comparison)}
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
      <div class="stack-list">${rows.slice(0, 5).map(renderHttpRow).join('')}</div>
    </section>
  `;
}

function renderHttpComparisonSection(comparison) {
  if (!comparison) return '';
  return `
    <section class="flow-section">
      <div class="flow-section-header">
        <h4>HTTP comparison</h4>
        ${makeBadge('passive vs active', 'accent')}
      </div>
      <div class="stack-list">
        ${renderSingleHttpComparison('Light Testing vs passive', comparison.light_vs_passive, comparison.passive, comparison.light)}
        ${renderSingleHttpComparison('PCAP-Mimic vs passive', comparison.mimic_vs_passive, comparison.passive, comparison.mimic)}
      </div>
    </section>
  `;
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
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Passive</span><span class="kv-value mono">${escapeHtml(formatHttpShape(passiveRow))}</span></div>
        <div><span class="kv-label">Active</span><span class="kv-value mono">${escapeHtml(formatHttpShape(candidateRow))}</span></div>
      </div>
      ${summary.changed_fields && summary.changed_fields.length ? `<div class="diff-list top-gap">${summary.changed_fields.map((item) => `<div class="diff-row"><span class="pill pill-warning">${escapeHtml(item.field)}</span><span class="diff-before mono">${escapeHtml(stringifySmall(item.passive))}</span><span class="diff-arrow">→</span><span class="diff-after mono">${escapeHtml(stringifySmall(item.candidate))}</span></div>`).join('')}</div>` : ''}
      ${summary.same_fields && summary.same_fields.length ? `<div class="inline-note top-gap"><span class="kv-label">Same</span><span class="kv-value">${escapeHtml(summary.same_fields.join(', '))}</span></div>` : ''}
    </article>
  `;
}

function formatHttpShape(row) {
  if (!row) return 'n/a';
  return `${row.method || 'HTTP'} ${row.full_url || row.uri || '/'} | ${row.status_code || 'n/a'} | ${row.content_type || 'n/a'}`;
}

function stringifySmall(value) {
  if (value === null || value === undefined || value === '') return 'n/a';
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function renderTlsRow(row) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title mono">TLS observation</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Role</span><span class="kv-value">${escapeHtml(row.tls_role || 'n/a')}</span></div>
        <div><span class="kv-label">Version</span><span class="kv-value mono">${escapeHtml(row.tls_version_offered || row.tls_version_negotiated || 'n/a')}</span></div>
        <div><span class="kv-label">SNI</span><span class="kv-value">${escapeHtml(row.sni || 'n/a')}</span></div>
        <div><span class="kv-label">Cipher</span><span class="kv-value mono">${escapeHtml(row.selected_cipher || 'n/a')}</span></div>
      </div>
    </article>
  `;
}

function renderCertRow(cert) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(cert.subject_dn || 'subject unavailable')}</div>
        ${makeBadge(cert.provenance || 'unknown', toneForProvenance(cert.provenance))}
      </div>
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Issuer</span><span class="kv-value">${escapeHtml(cert.issuer_dn || 'n/a')}</span></div>
        <div><span class="kv-label">Serial</span><span class="kv-value mono">${escapeHtml(cert.serial_number || 'n/a')}</span></div>
        <div><span class="kv-label">SAN JSON</span><span class="kv-value mono">${escapeHtml(cert.san_json || 'n/a')}</span></div>
        <div><span class="kv-label">Chain position</span><span class="kv-value">${escapeHtml(cert.chain_position ?? 'n/a')}</span></div>
      </div>
    </article>
  `;
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
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Status</span><span class="kv-value">${escapeHtml(row.status || 'n/a')}</span></div>
        <div><span class="kv-label">Started</span><span class="kv-value">${escapeHtml(row.started_at || 'n/a')}</span></div>
        <div><span class="kv-label">Completed</span><span class="kv-value">${escapeHtml(row.completed_at || 'n/a')}</span></div>
      </div>
      ${renderProbeSummary(row.probe_type, requestSummary, responseSummary)}
    </article>
  `;
}

function safeJsonParse(value) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try { return JSON.parse(value); } catch { return {}; }
}

function renderProbeSummary(probeType, requestSummary, responseSummary) {
  if (probeType === 'jarm') {
    return `
      <div class="kv-grid compact-grid top-gap">
        <div><span class="kv-label">JARM</span><span class="kv-value mono">${escapeHtml(responseSummary.result || 'n/a')}</span></div>
        <div><span class="kv-label">Command</span><span class="kv-value mono">${escapeHtml((requestSummary.command || []).join(' ') || 'n/a')}</span></div>
      </div>`;
  }
  if (probeType === 'tls_cert_grab') {
    const cert = responseSummary.certificate || {};
    return `
      <div class="kv-grid compact-grid top-gap">
        <div><span class="kv-label">Subject</span><span class="kv-value">${escapeHtml(cert.subject_dn || 'n/a')}</span></div>
        <div><span class="kv-label">Issuer</span><span class="kv-value">${escapeHtml(cert.issuer_dn || 'n/a')}</span></div>
        <div><span class="kv-label">Leaf SHA-256</span><span class="kv-value mono">${escapeHtml(cert.leaf_sha256 || 'n/a')}</span></div>
        <div><span class="kv-label">Server name</span><span class="kv-value">${escapeHtml(responseSummary.server_name || requestSummary.server_name || 'n/a')}</span></div>
      </div>`;
  }
  return `
    <div class="kv-grid compact-grid top-gap">
      <div><span class="kv-label">Method</span><span class="kv-value">${escapeHtml(requestSummary.method || 'n/a')}</span></div>
      <div><span class="kv-label">URL</span><span class="kv-value mono">${escapeHtml(requestSummary.url || 'n/a')}</span></div>
      <div><span class="kv-label">HTTP</span><span class="kv-value mono">${escapeHtml(responseSummary.status_line || 'n/a')}</span></div>
      <div><span class="kv-label">Type</span><span class="kv-value">${escapeHtml(responseSummary.content_type || 'n/a')}</span></div>
      <div><span class="kv-label">Location</span><span class="kv-value mono">${escapeHtml(responseSummary.location || 'n/a')}</span></div>
      <div><span class="kv-label">Preview</span><span class="kv-value mono">${escapeHtml(responseSummary.body_preview_utf8 || 'n/a')}</span></div>
    </div>`;
}

function renderEnrichmentRow(row) {
  return `
    <article class="data-card">
      <div class="flow-section-header">
        <div class="data-card-title">${escapeHtml(row.provider || 'provider')} → ${escapeHtml(row.target_value || 'target')}</div>
        ${makeBadge(row.provenance || 'unknown', toneForProvenance(row.provenance))}
      </div>
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Target type</span><span class="kv-value">${escapeHtml(row.target_type || 'n/a')}</span></div>
        <div><span class="kv-label">Query</span><span class="kv-value mono">${escapeHtml(row.provider_query || 'n/a')}</span></div>
        <div><span class="kv-label">Summary</span><span class="kv-value mono">${escapeHtml(row.result_summary_json || row.raw_result_json || 'n/a')}</span></div>
      </div>
    </article>
  `;
}

function renderFingerprintBreakdown(fingerprints, referenceMatches, shodanQueries, comparisonSummary) {
  if (!fingerprints.length) return 'No stored fingerprints yet for this flow.';
  return `<div class="stack-list">${fingerprints.map((fp) => {
    const key = `${fp.fingerprint_type}:${fp.fingerprint_value}`;
    const matchCount = (referenceMatches[key] || []).length;
    const comparison = comparisonSummary[fp.fingerprint_type] || null;
    const [comparisonLabel, comparisonTone] = labelForComparisonState(comparison?.state);
    return `
      <article class="data-card">
        <div class="flow-section-header">
          <div class="data-card-title mono">${escapeHtml(fp.fingerprint_type)}</div>
          <div class="flow-badges">
            ${makeBadge(fp.provenance || 'unknown', toneForProvenance(fp.provenance))}
            ${matchCount ? makeBadge(`${matchCount} reference match${matchCount === 1 ? '' : 'es'}`, 'success') : ''}
            ${comparison ? makeBadge(comparisonLabel, comparisonTone) : ''}
          </div>
        </div>
        <div class="mono fingerprint-value">${escapeHtml(fp.fingerprint_value)}</div>
        <div class="panel-actions top-gap">
          <button type="button" class="fingerprint-search-button" data-search-type="${escapeHtml(fp.fingerprint_type || 'auto')}" data-search-value="${escapeHtml(fp.fingerprint_value || '')}">Search this value</button>
        </div>
        ${shodanQueries[key] ? `<div class="inline-note"><span class="kv-label">Shodan</span><span class="mono">${escapeHtml(shodanQueries[key])}</span></div>` : ''}
      </article>`;
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
  if (httpComparison?.light_vs_passive) items.push(`<li><strong>HTTP Light Testing:</strong> ${escapeHtml(httpComparison.light_vs_passive.notes || httpComparison.light_vs_passive.state)}.</li>`);
  if (httpComparison?.mimic_vs_passive) items.push(`<li><strong>HTTP PCAP-Mimic:</strong> ${escapeHtml(httpComparison.mimic_vs_passive.notes || httpComparison.mimic_vs_passive.state)}.</li>`);
  items.push('<li><strong>Provenance:</strong> rows are labeled as <span class="mono">pcap_observed</span>, <span class="mono">pcap_derived</span>, <span class="mono">light_active_probe</span>, <span class="mono">third_party_enrichment</span>, or <span class="mono">pcap_mimic_active</span>.</li>');
  return `<ul class="analysis-list">${items.join('')}</ul>`;
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
      <div class="kv-grid compact-grid">
        <div><span class="kv-label">Type</span><span class="kv-value">${escapeHtml(match.match_type || 'n/a')}</span></div>
        <div><span class="kv-label">Context</span><span class="kv-value">${escapeHtml(match.subtitle || 'n/a')}</span></div>
        <div><span class="kv-label">Detail</span><span class="kv-value mono">${escapeHtml(JSON.stringify(match.detail || {}))}</span></div>
      </div>
      ${match.detail?.flow_id ? `<div class="panel-actions top-gap"><button type="button" class="flow-jump-button" data-flow-id="${escapeHtml(match.detail.flow_id)}">Open flow ${escapeHtml(match.detail.flow_id)}</button></div>` : ''}
    </article>
  `).join('')}</div>`;
}

function renderFlowDetail(data) {
  const mainHtml = `
    <div class="flow-report">
      ${makeFlowHeader(data.flow || {})}
      ${renderHttpSections(data.http || [], data.http_comparison || {})}
      ${makeObservationList('TLS observations', (data.tls || []).slice(0, 5), renderTlsRow)}
      ${makeObservationList('Certificates', (data.certificates || []).slice(0, 4), renderCertRow)}
      ${makeObservationList('Active probes', (data.active_probes || []).slice(0, 6), renderActiveProbeRow)}
      ${makeObservationList('Enrichments', (data.enrichments || []).slice(0, 4), renderEnrichmentRow)}
    </div>`;
  return {
    mainHtml,
    breakdownHtml: renderFingerprintBreakdown(data.fingerprints || [], data.reference_matches || {}, data.shodan_queries || {}, data.comparison_summary || {}),
    assessmentsHtml: renderAssessments(data.fingerprints || [], data.reference_matches || {}, data.shodan_queries || {}, data.certificates || [], data.comparison_summary || {}, data.http_comparison || {}),
    logText: `Loaded flow detail for flow ${data.flow?.id || 'n/a'}. HTTP rows=${(data.http || []).length}, TLS rows=${(data.tls || []).length}, certs=${(data.certificates || []).length}, active probes=${(data.active_probes || []).length}, fingerprints=${(data.fingerprints || []).length}, enrichments=${(data.enrichments || []).length}`,
  };
}

async function runReferenceLookup(source = 'right') {
  const valueEl = document.getElementById(source === 'top' ? 'quick-search-value' : 'reference-search-value');
  const typeEl = document.getElementById(source === 'top' ? 'quick-search-type' : 'reference-search-type');
  const resultsEl = document.getElementById('reference-search-results');
  if (!valueEl || !typeEl || !resultsEl) return;
  const value = valueEl.value.trim();
  const type = typeEl.value.trim();
  if (!value) {
    resultsEl.textContent = 'Enter a value to search.';
    return;
  }
  currentSearchState = { value, type };
  setSearchControls(value, type);
  resultsEl.textContent = 'Searching local data...';
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
  const mainOutput = document.getElementById('main-output');
  const breakdown = document.getElementById('ja-breakdown');
  const assessments = document.getElementById('indicator-assessments');
  const logBox = document.getElementById('log-box');
  if (!flowId) return;
  try {
    const resp = await fetch(`/api/flows/${flowId}`);
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Flow detail lookup failed');
    currentFlowId = Number(flowId);
    const rendered = renderFlowDetail(data);
    if (mainOutput) mainOutput.innerHTML = rendered.mainHtml;
    if (breakdown) breakdown.innerHTML = rendered.breakdownHtml;
    if (assessments) assessments.innerHTML = rendered.assessmentsHtml;
    if (logBox) logBox.textContent = rendered.logText;
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
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ force_refresh: false }),
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
    const resp = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Export failed');
    latestExport = data;
    if (logBox) logBox.innerHTML = `Export ready: <span class="mono">${escapeHtml(data.filename)}</span> <a href="${escapeHtml(data.download_url)}">download</a>`;
    const summary = document.getElementById('session-summary');
    if (summary) summary.innerHTML += `<li>Latest export: <span class="mono">${escapeHtml(data.filename)}</span></li>`;
    if (data.download_url) {
      const link = document.createElement('a'); link.href = data.download_url; link.download = data.filename; document.body.appendChild(link); link.click(); link.remove();
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
  const formData = new FormData(); formData.append('pcap', file);
  try {
    const resp = await fetch('/api/upload-pcap', { method: 'POST', body: formData });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'Upload failed');
    if (selector) {
      selector.innerHTML = '';
      const flows = data.flows || [];
      if (!flows.length) {
        const opt = document.createElement('option'); opt.textContent = 'No flows found'; selector.appendChild(opt); selector.disabled = true;
      } else {
        for (const flow of flows) {
          const opt = document.createElement('option'); opt.value = String(flow.id || flow.flow_key); opt.textContent = flow.selection_label || flow.flow_key; selector.appendChild(opt);
        }
        selector.disabled = false; selector.selectedIndex = 0;
      }
    }
    renderSummary(data.sample || {}, (data.flows || []).length, data.sha256, data.deduplicated, data.parse_warnings || []);
    if (mainOutput) {
      mainOutput.innerHTML = `
        <section class="flow-section flow-section-hero">
          <div class="flow-section-header">
            <h4>PCAP ingest complete</h4>
            ${makeBadge(data.deduplicated ? 'deduplicated' : 'new sample', data.deduplicated ? 'warning' : 'success')}
          </div>
          <div class="kv-grid compact-grid">
            <div><span class="kv-label">Sample</span><span class="kv-value">${escapeHtml(data.sample?.filename || file.name)}</span></div>
            <div><span class="kv-label">SHA-256</span><span class="kv-value mono">${escapeHtml(data.sha256 || 'n/a')}</span></div>
            <div><span class="kv-label">Conversations</span><span class="kv-value">${escapeHtml((data.flows || []).length)}</span></div>
          </div>
        </section>`;
    }
    if (logBox) {
      const warningTail = (data.parse_warnings || []).length ? ` Parse warnings: ${data.parse_warnings.length}.` : '';
      logBox.textContent = `${data.deduplicated ? 'Duplicate PCAP detected by SHA-256. Reused existing stored sample and flows.' : 'PCAP uploaded, hashed, stored, parsed, and observation extraction completed.'}${warningTail}`;
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

document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  document.getElementById('reference-search-button')?.addEventListener('click', () => runReferenceLookup('right'));
  document.getElementById('quick-search-button')?.addEventListener('click', () => runReferenceLookup('top'));
  document.getElementById('light-jarm-button')?.addEventListener('click', runLightJarm);
  document.getElementById('light-cert-button')?.addEventListener('click', runLightCert);
  document.getElementById('light-http-button')?.addEventListener('click', runLightHttp);
  document.getElementById('pcap-mimic-button')?.addEventListener('click', runPcapMimic);
  document.getElementById('shodan-enrich-button')?.addEventListener('click', runShodanEnrichment);
  document.getElementById('export-button')?.addEventListener('click', runExport);
  const fileInput = document.getElementById('pcap-file');
  const fileNameEl = document.getElementById('pcap-file-name');
  if (fileInput && fileNameEl) fileInput.addEventListener('change', () => { fileNameEl.value = fileInput.files && fileInput.files[0] ? fileInput.files[0].name : 'No file selected'; });
  document.getElementById('read-pcap-button')?.addEventListener('click', uploadPcap);
  const selector = document.getElementById('conversation-selector');
  if (selector) selector.addEventListener('change', async () => { if (selector.value) await loadFlowDetail(selector.value); });
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
    await runReferenceLookup('right');
  });
});
