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

let currentSample = null;
const packetDetailCache = new Map();
const packetUiState = new Map();
let drawerState = null;
let citationDrawerState = null;
let standaloneAnalysisResult = null;
let currentInputMode = 'pcap';
const SAVEABLE_ARTIFACT_TYPES = new Set(['ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4t', 'ja4ts', 'ja3', 'ja3s', 'hassh', 'hassh_server', 'ja4l', 'ja4ls', 'ja4ssh', 'ja4d', 'ja4d6']);
const appRuntime = {
  shodanConfigured: Boolean(globalThis?.JA42_BOOTSTRAP?.shodan_enabled),
};
const SOURCE_REGISTRY = {
  1: {
    id: 1,
    title: 'FoxIO JA4+ Overview',
    short: 'FoxIO JA4+',
    url: 'https://blog.foxio.io/ja4%2B-network-fingerprinting',
    citation: 'FoxIO Blog, “JA4+ Network Fingerprinting.”',
  },
  2: {
    id: 2,
    title: 'FoxIO JA4T Deep Dive',
    short: 'FoxIO JA4T',
    url: 'https://blog.foxio.io/ja4t-tcp-fingerprinting',
    citation: 'FoxIO Blog, “JA4T: TCP Fingerprinting.”',
  },
  3: {
    id: 3,
    title: 'FoxIO Surfshark and NordVPN Investigation',
    short: 'FoxIO VPN JA4T',
    url: 'https://blog.foxio.io/investigating-surfshark-and-nordvpn-with-ja4t',
    citation: 'FoxIO Blog, “Investigating Surfshark and NordVPN with JA4T.”',
  },
  4: {
    id: 4,
    title: 'FoxIO JA4 Repository',
    short: 'FoxIO JA4 Repo',
    url: 'https://github.com/FoxIO-LLC/ja4',
    citation: 'FoxIO-LLC, “ja4” repository.',
  },
  5: {
    id: 5,
    title: 'Salesforce JA3',
    short: 'JA3',
    url: 'https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41/',
    citation: 'Salesforce Engineering, “Open Sourcing JA3.”',
  },
  6: {
    id: 6,
    title: 'Salesforce JA3 and JA3S',
    short: 'JA3/JA3S',
    url: 'https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/',
    citation: 'Salesforce Engineering, “TLS Fingerprinting with JA3 and JA3S.”',
  },
  7: {
    id: 7,
    title: 'Salesforce JARM',
    short: 'JARM',
    url: 'https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/',
    citation: 'Salesforce Engineering, “Easily Identify Malicious Servers on the Internet with JARM.”',
  },
  8: {
    id: 8,
    title: 'RFC 9110 HTTP Semantics',
    short: 'RFC 9110',
    url: 'https://www.rfc-editor.org/info/rfc9110/',
    citation: 'RFC 9110, HTTP Semantics.',
  },
  9: {
    id: 9,
    title: 'RFC 9293 TCP',
    short: 'RFC 9293',
    url: 'https://www.rfc-editor.org/rfc/rfc9293',
    citation: 'RFC 9293, Transmission Control Protocol (TCP).',
  },
  10: {
    id: 10,
    title: 'RFC 7323 TCP High Performance Extensions',
    short: 'RFC 7323',
    url: 'https://www.rfc-editor.org/info/rfc7323/',
    citation: 'RFC 7323, TCP Extensions for High Performance.',
  },
  11: {
    id: 11,
    title: 'RFC 6691 TCP Options and MSS',
    short: 'RFC 6691',
    url: 'https://www.rfc-editor.org/rfc/rfc6691',
    citation: 'RFC 6691, TCP Options and Maximum Segment Size (MSS).',
  },
  12: {
    id: 12,
    title: 'RFC 4253 SSH Transport Layer Protocol',
    short: 'RFC 4253',
    url: 'https://www.rfc-editor.org/info/rfc4253/',
    citation: 'RFC 4253, The Secure Shell (SSH) Transport Layer Protocol.',
  },
  13: {
    id: 13,
    title: 'RFC 4254 SSH Connection Protocol',
    short: 'RFC 4254',
    url: 'https://www.rfc-editor.org/rfc/rfc4254',
    citation: 'RFC 4254, The Secure Shell (SSH) Connection Protocol.',
  },
  14: {
    id: 14,
    title: 'IANA TCP Option Kinds',
    short: 'IANA TCP Options',
    url: 'https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml',
    citation: 'IANA, TCP Option Kind Numbers.',
  },
  15: {
    id: 15,
    title: 'Trisul SSH Tunnel Detection',
    short: 'Trisul SSH Tunnels',
    url: 'https://www.trisul.org/blog/detecting-ssh-tunnels/',
    citation: 'Trisul Blog, “Detecting SSH tunnels.”',
  },
  16: {
    id: 16,
    title: 'Trisul SSH Traffic Analysis',
    short: 'Trisul SSH Analysis',
    url: 'https://www.trisul.org/blog/traffic-analysis-of-secure-shell-ssh/',
    citation: 'Trisul Blog, “Traffic analysis of Secure Shell (SSH).”',
  },
  17: {
    id: 17,
    title: 'Shodan Host Information API',
    short: 'Shodan Host API',
    url: 'https://developer.shodan.io/api',
    citation: 'Shodan Developer API, Host Information endpoint.',
  },
  18: {
    id: 18,
    title: 'p0f Passive OS Fingerprinting',
    short: 'p0f',
    url: 'https://github.com/skord/p0f',
    citation: 'Michal Zalewski, “p0f” passive OS fingerprinting tool repository and documentation.',
  },
  19: {
    id: 19,
    title: 'PacketBomb Throughput and TCP Windows',
    short: 'PacketBomb TCP Windows',
    url: 'https://packetbomb.com/understanding-throughput-and-tcp-windows/',
    citation: 'PacketBomb, “Understanding Throughput and TCP Windows.”',
  },
  20: {
    id: 20,
    title: 'PacketBomb TCP Sequence Number Analysis',
    short: 'PacketBomb TCP Seq',
    url: 'https://packetbomb.com/how-to-do-tcp-sequence-number-analysis/',
    citation: 'PacketBomb, “How to Do TCP Sequence Number Analysis.”',
  },
  21: {
    id: 21,
    title: 'PacketBomb tcptrace Time-Sequence Graph',
    short: 'PacketBomb tcptrace',
    url: 'https://packetbomb.com/understanding-the-tcptrace-time-sequence-graph-in-wireshark/',
    citation: 'PacketBomb, “Understanding the tcptrace Time-Sequence Graph in Wireshark.”',
  },
  22: {
    id: 22,
    title: 'PacketBomb Large Packets and MTU',
    short: 'PacketBomb MTU',
    url: 'https://packetbomb.com/how-can-the-packet-size-be-greater-than-the-mtu/',
    citation: 'PacketBomb, “How Can the Packet Size Be Greater than the MTU?”',
  },
};

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function logLine(message) {
  const box = document.getElementById('log-box');
  if (!box) return;
  const stamp = new Date().toISOString();
  box.textContent = box.textContent === 'No logs yet.'
    ? `[${stamp}] ${message}`
    : `${box.textContent}\n[${stamp}] ${message}`;
}

function getPacketState(packetId) {
  if (!packetUiState.has(packetId)) {
    packetUiState.set(packetId, {
      analystOpen: true,
      contextOpen: true,
      inferenceOpen: true,
      inspectorLayersOpen: true,
      inspectorHexOpen: true,
      layerNodeState: {},
      jarmNotesOpen: true,
      jarmMatchesOpen: true,
      jarmLoading: false,
      jarmError: '',
      jarmResult: null,
      jarmTargetPort: '',
      shodanLoading: false,
      shodanError: '',
      shodanResult: null,
      shodanKeyEditorOpen: !appRuntime.shodanConfigured,
      shodanKeyStatus: '',
    });
  }
  return packetUiState.get(packetId);
}

function isSaveableArtifactType(artifactType) {
  return SAVEABLE_ARTIFACT_TYPES.has(String(artifactType || '').trim().toLowerCase());
}

function extractDestinationDomain(endpointText) {
  const match = String(endpointText || '').match(/\(([^()]+)\)\s*$/);
  return match ? match[1].trim() : '';
}

function escapeAttribute(value) {
  return escapeHtml(value ?? '');
}

function getPacketDetailPayload(packetId) {
  return packetDetailCache.get(packetId) || null;
}

function getArtifactById(packetId, artifactId) {
  const payload = getPacketDetailPayload(packetId);
  const artifacts = payload?.artifacts || [];
  return artifacts.find((artifact) => Number(artifact.id) === Number(artifactId)) || null;
}

function getRelatedArtifactValues(packetId, focusedArtifact = null) {
  const payload = getPacketDetailPayload(packetId);
  const artifacts = payload?.artifacts || [];
  const values = {};
  for (const artifact of artifacts) {
    const type = String(artifact.artifact_type || '').trim().toLowerCase();
    if (!isSaveableArtifactType(type)) continue;
    if (!values[type]) values[type] = String(artifact.artifact_value || '').trim();
  }
  if (focusedArtifact) {
    const type = String(focusedArtifact.artifact_type || '').trim().toLowerCase();
    if (type) values[type] = String(focusedArtifact.artifact_value || '').trim();
  }
  return values;
}

function closeDrawer() {
  drawerState = null;
  document.getElementById('drawer-overlay')?.setAttribute('hidden', 'hidden');
  const panel = document.getElementById('drawer-panel');
  if (panel) {
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
  }
  const body = document.getElementById('drawer-body');
  if (body) body.innerHTML = '';
}

function closeCitationDrawer() {
  citationDrawerState = null;
  const panel = document.getElementById('citation-panel');
  if (!panel) return;
  panel.classList.remove('open');
  panel.setAttribute('aria-hidden', 'true');
}

function openCitationDrawer(sourceId) {
  const panel = document.getElementById('citation-panel');
  const body = document.getElementById('citation-body');
  if (!panel || !body) return;
  citationDrawerState = { sourceId: Number(sourceId) };
  body.innerHTML = renderCitationList(Number(sourceId));
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  body.querySelector(`[data-citation-id="${Number(sourceId)}"]`)?.scrollIntoView({
    block: 'center',
    behavior: 'smooth',
  });
}

function renderCitationList(activeSourceId) {
  return Object.values(SOURCE_REGISTRY)
    .sort((a, b) => a.id - b.id)
    .map((source) => `
      <article class="citation-card ${Number(source.id) === Number(activeSourceId) ? 'citation-card-active' : ''}" data-citation-id="${source.id}">
        <div class="citation-card-number">[${source.id}]</div>
        <div class="citation-card-body">
          <div class="citation-card-title">${escapeHtml(source.title)}</div>
          <div class="citation-card-text">${escapeHtml(source.citation)}</div>
          <a class="citation-card-link" href="${escapeAttribute(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.url)}</a>
        </div>
      </article>
    `).join('');
}

function openDrawer({ kicker, title, bodyHtml, onOpen }) {
  drawerState = { kicker, title };
  const overlay = document.getElementById('drawer-overlay');
  const panel = document.getElementById('drawer-panel');
  const drawerKicker = document.getElementById('drawer-kicker');
  const drawerTitle = document.getElementById('drawer-title');
  const body = document.getElementById('drawer-body');
  if (!overlay || !panel || !drawerKicker || !drawerTitle || !body) return;
  drawerKicker.textContent = kicker || 'Analyst Save';
  drawerTitle.textContent = title || 'Save Value';
  body.innerHTML = bodyHtml || '';
  overlay.removeAttribute('hidden');
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  if (typeof onOpen === 'function') onOpen(body);
}

function defaultExportName() {
  const today = new Date().toISOString().slice(0, 10);
  return `unnamed-${today}`;
}

function openExportDrawer() {
  const html = `
    <form id="export-form" class="drawer-form">
      <div class="drawer-status">
        Export the real analyst tables from JA-Bench. Packet/sample cache history is not included in this menu anymore.
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="export-name">Export Name</label>
          <input id="export-name" name="export_name" type="text" value="${escapeAttribute(defaultExportName())}" placeholder="unnamed-YYYY-MM-DD">
          <div class="drawer-helper">Type a new filename here if you want something more specific before exporting.</div>
        </div>
        <div class="drawer-field">
          <label for="export-format">Format</label>
          <select id="export-format" name="export_format">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="jsonl">JSONL / NDJSON</option>
          </select>
        </div>
        <div class="drawer-field">
          <label for="export-scope">Scope</label>
          <select id="export-scope" name="scope">
            <option value="analyst_tables" selected>JA + JARM Tables</option>
            <option value="references">JA Reference Table</option>
            <option value="jarm">JARM Table</option>
          </select>
        </div>
      </div>
      <div id="export-scope-note" class="drawer-helper"></div>
      <div id="export-status" class="drawer-helper"></div>
      <div class="action-button-group">
        <button type="submit">Export</button>
        <button type="button" data-drawer-close="true">Cancel</button>
      </div>
    </form>
  `;

  openDrawer({
    kicker: 'Export',
    title: 'Export Results',
    bodyHtml: html,
    onOpen: (body) => {
      const form = body.querySelector('#export-form');
      const formatSelect = body.querySelector('#export-format');
      const scopeSelect = body.querySelector('#export-scope');
      const updateExportFormState = () => syncExportFormState(formatSelect, scopeSelect, body.querySelector('#export-scope-note'));
      body.querySelector('[data-drawer-close="true"]')?.addEventListener('click', closeDrawer);
      formatSelect?.addEventListener('change', updateExportFormState);
      scopeSelect?.addEventListener('change', updateExportFormState);
      updateExportFormState();
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitExportForm(form);
      });
    },
  });
}

function syncExportFormState(formatSelect, scopeSelect, noteEl) {
  if (!formatSelect || !scopeSelect || !noteEl) return;
  const scope = String(scopeSelect.value || '').trim().toLowerCase();
  const notes = {
    analyst_tables: 'Exports both analyst-facing tables: the JA reference table and the saved JARM table. This is the broadest useful analyst export.',
    references: 'Exports the JA reference table from reference_fingerprints, including dataset metadata so seeded and analyst-curated entries stay distinguishable.',
    jarm: 'Exports the saved JARM table from jarm_fingerprints, including host, IP, port, destination domain, and analyst note fields.',
  };
  noteEl.textContent = notes[scope] || '';
}

async function submitExportForm(form) {
  const status = document.getElementById('export-status');
  const payload = Object.fromEntries(new FormData(form).entries());
  if (status) status.textContent = 'Building export...';
  try {
    const response = await fetch('/api/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const result = await response.json();
      throw new Error(result.error || 'Export failed');
    }
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const filename = parseDownloadFilename(disposition) || `${String(payload.export_name || 'ja-bench-export').trim() || 'ja-bench-export'}.${payload.export_format || 'json'}`;
    triggerBlobDownload(blob, filename);
    closeDrawer();
    logLine(`Exported ${payload.scope} as ${payload.export_format}: ${filename}.`);
  } catch (error) {
    if (status) status.textContent = error.message;
    logLine(`Export failed: ${error.message}`);
  }
}

function parseDownloadFilename(disposition) {
  const utf8Match = String(disposition || '').match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match) return decodeURIComponent(utf8Match[1]);
  const plainMatch = String(disposition || '').match(/filename="?([^"]+)"?/i);
  return plainMatch ? plainMatch[1] : '';
}

function triggerBlobDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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

function setInputMode(mode) {
  const nextMode = mode === 'direct' ? 'direct' : 'pcap';
  currentInputMode = nextMode;

  const pcapPanel = document.getElementById('pcap-input-panel');
  const directPanel = document.getElementById('direct-hash-panel');
  const pcapButton = document.getElementById('mode-pcap-button');
  const directButton = document.getElementById('mode-direct-button');

  pcapPanel?.toggleAttribute('hidden', nextMode !== 'pcap');
  directPanel?.toggleAttribute('hidden', nextMode !== 'direct');

  pcapButton?.classList.toggle('mode-button-active', nextMode === 'pcap');
  directButton?.classList.toggle('mode-button-active', nextMode === 'direct');

  if (pcapButton) pcapButton.setAttribute('aria-selected', nextMode === 'pcap' ? 'true' : 'false');
  if (directButton) directButton.setAttribute('aria-selected', nextMode === 'direct' ? 'true' : 'false');
}

function setSummary(sample) {
  const container = document.getElementById('sample-summary');
  const zeek = sample?.zeek_summary || {};
  const zeekHighlights = Array.isArray(zeek.highlights) ? zeek.highlights : [];
  if (!container) return;
  if (!sample) {
    container.innerHTML = '<div class="summary-empty">No PCAP loaded yet.</div>';
    return;
  }

  container.innerHTML = [
    summaryCard('Filename', sample.filename || 'n/a'),
    summaryCard('SHA-256', sample.sha256 || 'n/a', true),
    summaryCard('Packets', sample.packet_count ?? '0'),
    summaryCard('Capture Start', sample.capture_start_ts || 'n/a'),
    summaryCard('Capture End', sample.capture_end_ts || 'n/a'),
    summaryCard('Zeek Status', zeek.status || 'n/a'),
    summaryCard('Zeek Highlights', zeekHighlights.length ? zeekHighlights.map((item) => `${item.log}: ${item.line_count}`).join(', ') : 'none'),
    summaryCard('Artifacts', sample.parse_summary?.artifact_count ?? '0'),
  ].join('');
}

function summaryCard(label, value, mono = false) {
  return `
    <article class="summary-card">
      <span class="label">${escapeHtml(label)}</span>
      <span class="value ${mono ? 'mono' : ''}">${escapeHtml(value)}</span>
    </article>
  `;
}

function setStats(sample, packets, counts = null) {
  if (counts) {
    document.getElementById('stat-runs').textContent = String(counts.runs);
    document.getElementById('stat-samples').textContent = String(counts.samples);
    document.getElementById('stat-packets').textContent = String(counts.packets);
    document.getElementById('stat-artifacts').textContent = String(counts.artifacts);
    return;
  }
  document.getElementById('stat-packets').textContent = String(packets.length);
  document.getElementById('stat-artifacts').textContent = String(sample?.parse_summary?.artifact_count || 0);
}

function setWindowStatus(message) {
  const el = document.getElementById('packet-window-status');
  if (el) el.textContent = message;
}

function renderPackets(rows) {
  const body = document.getElementById('packet-table-body');
  if (!body) return;
  if (!rows.length) {
    body.innerHTML = '<tr class="empty-row"><td colspan="5">No packets parsed.</td></tr>';
    return;
  }

  body.innerHTML = rows.map((row) => `
    <tr class="packet-row" data-packet-id="${row.id}">
      <td><button class="expander-button" data-packet-id="${row.id}" aria-expanded="false">+</button></td>
      <td>${escapeHtml(row.packet_number)}</td>
      <td class="mono">${renderEndpointText(row)}</td>
      <td>${renderArtifactSummary(row.artifact_summary || [])}</td>
      <td><div>${escapeHtml(row.protocol || row.transport || 'n/a')}</div><div class="match-subtle">${escapeHtml(row.ts_text || 'n/a')}</div></td>
    </tr>
    <tr class="detail-row" id="detail-row-${row.id}" hidden>
      <td colspan="5"><div class="detail-shell empty-detail">Expand to load packet detail.</div></td>
    </tr>
  `).join('');

  body.querySelectorAll('.expander-button').forEach((button) => {
    button.addEventListener('click', () => togglePacketDetail(Number(button.dataset.packetId), button));
  });
}

function renderEndpointText(row) {
  const endpointText = String(row?.endpoint_text || '').trim();
  const fallbackText = String(row?.protocol || row?.transport || 'unknown');
  const text = endpointText || fallbackText;
  const domainMatch = text.match(/^(.*?\S)\s+\(([^()]+)\)$/);
  if (!domainMatch) return escapeHtml(text);
  return `${escapeHtml(domainMatch[1])} <span class="endpoint-domain">(${escapeHtml(domainMatch[2])})</span>`;
}

function renderArtifactSummary(artifacts) {
  if (!artifacts.length) return '<span class="match-subtle">No derived artifacts</span>';
  return `
    <div class="artifact-list">
      ${artifacts.map((artifact) => `
        <span class="pill">
          <span class="pill-type">${escapeHtml(artifact.artifact_type.toUpperCase())}</span>
          <span>${escapeHtml(artifact.artifact_value)}</span>
        </span>
      `).join('')}
    </div>
  `;
}

async function togglePacketDetail(packetId, button) {
  const detailRow = document.getElementById(`detail-row-${packetId}`);
  if (!detailRow) return;
  const isOpen = !detailRow.hidden;
  if (isOpen) {
    detailRow.hidden = true;
    button.textContent = '+';
    button.setAttribute('aria-expanded', 'false');
    return;
  }

  if (!detailRow.dataset.loaded) {
    detailRow.querySelector('.detail-shell').textContent = 'Loading packet detail...';
    try {
      const response = await fetch(`/api/packets/${packetId}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || 'Packet detail request failed');
      packetDetailCache.set(packetId, payload);
      renderDetailRow(packetId);
      detailRow.dataset.loaded = 'true';
    } catch (error) {
      detailRow.querySelector('.detail-shell').innerHTML = `<div class="empty-detail">${escapeHtml(error.message)}</div>`;
      logLine(`Packet detail failed for packet row ${packetId}: ${error.message}`);
    }
  }

  detailRow.hidden = false;
  button.textContent = '−';
  button.setAttribute('aria-expanded', 'true');
}

function renderDetailRow(packetId) {
  const detailRow = document.getElementById(`detail-row-${packetId}`);
  const payload = packetDetailCache.get(packetId);
  if (!detailRow || !payload) return;
  detailRow.querySelector('.detail-shell').innerHTML = renderPacketDetail(payload);
  wirePacketDetailActions(packetId);
}

function renderPacketDetail(payload) {
  const artifacts = payload.artifacts || [];
  const packetId = Number(payload?.packet?.id || 0);
  const sections = [];
  if (!artifacts.length) {
    sections.push('<div class="empty-detail">No derived JA-family artifacts were produced for this packet.</div>');
  } else {
    sections.push(artifacts.map((artifact) => renderArtifactCard(packetId, artifact)).join(''));
  }
  sections.push(renderPacketInspector(payload));
  sections.push(renderAnalystBox(payload));
  return sections.join('');
}

function renderPacketInspector(payload) {
  const packet = payload?.packet || {};
  const packetId = Number(packet.id);
  const inspector = packet.packet_inspector || {};
  const state = getPacketState(packetId);
  const shodanTarget = getShodanTarget(packet, inspector);
  const destinationDomain = inspector.destination_domain || extractDestinationDomain(packet.endpoint_text);
  const targetLabel = destinationDomain || packet.dst_ip || 'No public target extracted';
  const passiveFields = [
    ['destination', targetLabel],
    ['dst ip', packet.dst_ip || 'n/a'],
    ...(inspector.src_mac ? [['src mac', inspector.src_mac_display || inspector.src_mac]] : []),
    ...(inspector.dst_mac ? [['dst mac', inspector.dst_mac_display || inspector.dst_mac]] : []),
    ['user-agent', inspector.user_agent || 'not present in this packet'],
    ['cert issuer', inspector.certificate_authority || 'not present in this packet'],
    ['cert subject', inspector.certificate_subject || 'not present in this packet'],
  ];

  return `
    <details class="matches-box" ${state.contextOpen ? 'open' : ''} data-state-key="contextOpen">
      <summary>Context</summary>
      <div class="context-shell">
        <section class="packet-inspector-shell">
          <div class="packet-inspector-left">
            <details class="packet-pane" ${state.inspectorLayersOpen ? 'open' : ''} data-state-key="inspectorLayersOpen">
              <summary>Packet Layers</summary>
              <div class="packet-pane-body">
                ${renderLayerTree(packetId, inspector.layers || [])}
              </div>
            </details>
            <details class="packet-pane" ${state.inspectorHexOpen ? 'open' : ''} data-state-key="inspectorHexOpen">
              <summary>Bytes / Hex</summary>
              <div class="packet-pane-body">
                ${renderHexTable(inspector.hexdump || [])}
              </div>
            </details>
          </div>
          <div class="packet-pane packet-pane-right">
            <div class="packet-pane-header">Packet Context</div>
            <div class="context-grid">
              ${passiveFields.map(([label, value]) => `
                <div class="context-item">
                  <span class="kv-label">${escapeHtml(label)}</span>
                  <div class="kv-value">${escapeHtml(value)}</div>
                </div>
              `).join('')}
            </div>
            <div class="action-button-group">
              <button type="button" data-action="run-shodan" data-packet-id="${packetId}" ${(state.shodanLoading || !shodanTarget.enabled) ? 'disabled' : ''}>${state.shodanLoading ? 'Running Shodan...' : 'Enrich with Shodan'}</button>
              <button type="button" data-action="toggle-shodan-key">${state.shodanKeyEditorOpen ? 'Hide Key Editor' : (appRuntime.shodanConfigured ? 'Change Shodan Key' : 'Enter Shodan Key')}</button>
            </div>
            ${!shodanTarget.enabled ? `<div class="match-subtle">${escapeHtml(shodanTarget.reason)}</div>` : ''}
            ${renderShodanKeyEditor(state)}
            ${state.shodanError ? `<div class="status-callout status-callout-danger">${escapeHtml(state.shodanError)}</div>` : ''}
            ${state.shodanKeyStatus ? `<div class="status-callout">${escapeHtml(state.shodanKeyStatus)}</div>` : ''}
            ${state.shodanResult ? renderShodanResult(state.shodanResult, packet) : ''}
          </div>
        </section>
      </div>
    </details>
  `;
}

function renderLayerTree(packetId, layers) {
  if (!layers.length) return '<div class="empty-detail">No decoded layers were available.</div>';
  const state = getPacketState(packetId);
  const layerNodeState = state.layerNodeState || {};
  return `
    <div class="layer-tree">
      ${layers.map((layer, index) => `
        <details class="layer-node" data-layer-node-key="${escapeAttribute(`${index}:${layer.name}`)}" ${layerNodeState[`${index}:${layer.name}`] ? 'open' : ''}>
          <summary>${escapeHtml(layer.name)} <span class="layer-count">${escapeHtml(layer.field_count || 0)} fields</span></summary>
          <div class="layer-fields">
            ${(layer.fields || []).map((field) => `
              <div class="layer-field">
                <span class="kv-label">${escapeHtml(field.name)}</span>
                <div class="kv-value">${escapeHtml(field.value)}</div>
              </div>
            `).join('')}
          </div>
        </details>
      `).join('')}
    </div>
  `;
}

function renderHexTable(rows) {
  if (!rows.length) return '<div class="empty-detail">No packet bytes were available.</div>';
  return `
    <div class="hex-table">
      ${rows.map((row) => `
        <div class="hex-row">
          <span class="hex-offset">${escapeHtml(row.offset)}</span>
          <span class="hex-bytes">${escapeHtml(row.hex)}</span>
          <span class="hex-ascii">${escapeHtml(row.ascii)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function renderShodanKeyEditor(state) {
  if (!state.shodanKeyEditorOpen) return '';
  return `
    <div class="collapsible-panel open">
      <form id="shodan-key-form" class="inline-form">
        <label for="shodan-api-key">Shodan API Key</label>
        <input id="shodan-api-key" name="api_key" type="password" value="" placeholder="${appRuntime.shodanConfigured ? 'Enter a replacement key' : 'Enter a Shodan API key'}" autocomplete="off">
        <div class="action-button-group">
          <button type="submit">Save and Test Key</button>
          ${appRuntime.shodanConfigured ? '<button type="button" data-action="collapse-shodan-key">Collapse</button>' : ''}
        </div>
      </form>
    </div>
  `;
}

function renderShodanResult(result, packet = {}) {
  const hostnameSearch = result.hostname_search;
  const hostLookup = result.host_lookup;
  const packetDstIp = String(packet?.dst_ip || '').trim();
  return `
    <div class="shodan-result-grid">
      ${hostnameSearch ? `
        <div class="result-card">
          <div class="action-row-title">Hostname Search</div>
          <div class="match-subtle">${escapeHtml(result.hostname_query || '')}</div>
          <div class="match-subtle">${escapeHtml(hostnameSearch.total ?? 0)} result(s)</div>
          ${(hostnameSearch.total || 0) > 1 ? '<div class="status-callout">Multiple hostname-search IPs usually mean the hostname has been observed on different hosts, edges, or times. The packet destination IP is still the strongest evidence for this row.</div>' : ''}
          ${(hostnameSearch.matches || []).map((match) => `
            <div class="result-line">
              <div class="kv-value">${escapeHtml(match.ip || 'n/a')}</div>
              <div class="match-subtle">${escapeHtml(match.organization || '')}${match.location ? `, ${escapeHtml(match.location)}` : ''}</div>
              ${match.ip && (match.ip === result.primary_ip || match.ip === packetDstIp) ? '<div class="match-subtle">selected for this packet row</div>' : ''}
            </div>
          `).join('')}
          ${result.selection_note ? `<div class="status-callout">${escapeHtml(result.selection_note)}</div>` : ''}
        </div>
      ` : ''}
      ${hostLookup ? `
        <div class="result-card">
          <div class="action-row-title">Host Summary</div>
          <div class="match-subtle">${escapeHtml(hostLookup.ip || result.primary_ip || 'n/a')}</div>
          <div class="context-grid">
            ${renderContextItem('domains', (hostLookup.domains || []).join(', ') || 'n/a')}
            ${renderContextItem('location', hostLookup.location || 'n/a')}
            ${renderContextItem('organization', hostLookup.organization || 'n/a')}
            ${renderContextItem('asn', hostLookup.asn || 'n/a')}
            ${renderContextItem('operating system', hostLookup.operating_system || 'n/a')}
            ${renderContextItem('web technologies', (hostLookup.technologies || []).join(', ') || 'n/a')}
            ${renderContextItem('open ports', (hostLookup.ports || []).join(', ') || 'n/a')}
            ${renderContextItem('cert issuer', hostLookup.certificate?.issuer || 'n/a')}
            ${renderContextItem('cert serial', hostLookup.certificate?.serial || 'n/a')}
          </div>
          <div class="service-list">
            ${(hostLookup.services || []).map((service) => `
              <div class="service-card">
                <div class="action-row-title">Port ${escapeHtml(service.port || '?')}</div>
                <div class="match-subtle">${escapeHtml(service.product || service.transport || '')}${service.version ? ` ${escapeHtml(service.version)}` : ''}</div>
                ${service.http_status ? `<div class="kv-value">HTTP ${escapeHtml(service.http_status)}</div>` : ''}
                ${service.http_location ? `<div class="match-subtle">Location: ${escapeHtml(service.http_location)}</div>` : ''}
                ${service.http_server ? `<div class="match-subtle">Server: ${escapeHtml(service.http_server)}</div>` : ''}
                ${service.data ? `<pre class="service-data">${escapeHtml(service.data)}</pre>` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}
    </div>
  `;
}

function renderContextItem(label, value) {
  return `
    <div class="context-item">
      <span class="kv-label">${escapeHtml(label)}</span>
      <div class="kv-value">${escapeHtml(value)}</div>
    </div>
  `;
}

function renderArtifactCard(packetId, artifact) {
  const matches = artifact.matches || [];
  const bestMatch = matches[0];
  const matchClass = bestMatch?.match_kind === 'exact' ? 'match-note exact' : 'match-note';
  const matchText = bestMatch?.note || 'No historical match found';

  return `
    <article class="artifact-card">
      <header class="artifact-card-header">
        <div>
          <div class="match-subtle">${escapeHtml(artifact.artifact_type.toUpperCase())}</div>
          <div class="artifact-card-title">${escapeHtml(artifact.artifact_value)}</div>
        </div>
        <div class="${matchClass}">${escapeHtml(matchText)}</div>
      </header>
      <div class="artifact-body">
        ${renderBreakdownGrid(artifact)}
        ${renderRawGrid(artifact)}
        ${renderInferenceBox(packetId, artifact)}
        ${renderMatches(matches)}
      </div>
    </article>
  `;
}

function renderBreakdownGrid(artifact) {
  const parts = artifact?.parts || {};
  const entries = Object.entries(parts || {}).filter(([, value]) => value !== null && value !== undefined && value !== '');
  if (!entries.length) return '<div class="empty-detail">No field breakdown available.</div>';
  return `
    <div class="kv-grid">
      ${entries.map(([label, value]) => {
        const explained = explainArtifactPart(artifact, label, value);
        return `
        <div class="kv-item">
          <span class="kv-label">${escapeHtml(label)}</span>
          <span class="kv-value">${escapeHtml(explained.displayValue)}${explained.inlineHint ? ` - ${escapeHtml(explained.inlineHint)}` : ''}</span>
          ${explained.note ? `<span class="kv-note">${escapeHtml(explained.note)}</span>` : ''}
        </div>
      `;
      }).join('')}
    </div>
  `;
}

function renderRawGrid(artifact) {
  const lines = [];
  if (artifact.raw_fingerprint) lines.push(['raw', artifact.raw_fingerprint]);
  if (artifact.raw_original_order) lines.push(['raw original order', artifact.raw_original_order]);
  if (!lines.length) return '';
  return `
    <div class="raw-grid">
      ${lines.map(([label, value]) => `
        <div class="raw-line">
          <span class="kv-label">${escapeHtml(label)}</span>
          <div class="kv-value">${escapeHtml(value)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderInferenceBox(packetId, artifact) {
  const state = getPacketState(packetId);
  const inferences = inferArtifact(packetId, artifact);
  if (!inferences.length) return '';
  return `
    <details class="matches-box inference-box" ${state.inferenceOpen ? 'open' : ''} data-state-key="inferenceOpen">
      <summary>Inferences &amp; Conclusions</summary>
      <div class="inference-list">
        ${inferences.map((item) => renderInferenceItem(item)).join('')}
      </div>
    </details>
  `;
}

function renderInferenceItem(item) {
  const kind = String(item?.kind || 'inference');
  const sourceId = Number(item?.sourceId || 0);
  return `
    <div class="inference-item inference-item-${escapeAttribute(kind)}">
      <div class="inference-item-header">
        <span class="inference-kind">${escapeHtml(kind === 'conclusion' ? 'Conclusion' : 'Inference')}</span>
        ${sourceId ? `<button type="button" class="footnote-button" data-action="open-citation" data-source-id="${sourceId}" aria-label="Open citation ${sourceId}">[${sourceId}]</button>` : ''}
      </div>
      <div>${escapeHtml(item?.text || '')}</div>
    </div>
  `;
}

function renderStandaloneInferenceBox(artifact) {
  const inferences = inferArtifact(null, artifact);
  if (!inferences.length) return '';
  return `
    <details class="matches-box inference-box" open>
      <summary>Inferences &amp; Conclusions</summary>
      <div class="inference-list">
        ${inferences.map((item) => renderInferenceItem(item)).join('')}
      </div>
    </details>
  `;
}

function renderStandaloneMatches(result) {
  const referenceMatches = result?.reference_matches || [];
  const jarmMatches = result?.jarm_matches || [];
  if (referenceMatches.length) return renderMatches(referenceMatches);
  if (jarmMatches.length) return renderStandaloneJarmMatches(jarmMatches);
  return '';
}

function renderStandaloneJarmMatches(matches) {
  if (!matches.length) return '';
  return `
    <details class="matches-box" open>
      <summary>Saved JARM Matches</summary>
      <div class="jarm-match-list">
        ${matches.map((match) => `
          <div class="jarm-match-card">
            <div class="action-row-title">${escapeHtml(match.note || 'JARM match')}</div>
            <div class="jarm-match-value">${escapeHtml(match.saved?.jarm_fingerprint || '')}</div>
            <div class="match-subtle">${escapeHtml(match.saved?.target_host || '')}${match.saved?.target_ip ? ` / ${escapeHtml(match.saved.target_ip)}` : ''}</div>
            ${match.saved?.destination_domain ? `<div class="match-subtle">domain: ${escapeHtml(match.saved.destination_domain)}</div>` : ''}
            ${match.saved?.analyst_note ? `<div class="match-subtle">note: ${escapeHtml(match.saved.analyst_note)}</div>` : ''}
          </div>
        `).join('')}
      </div>
    </details>
  `;
}

function renderStandaloneAnalystBox(result) {
  const artifact = result?.artifact || {};
  const artifactType = String(artifact.artifact_type || '').trim().toLowerCase();
  const title = artifactType === 'jarm' ? 'Save JARM' : 'Save Reference';
  const subtitle = artifactType === 'jarm'
    ? 'Store this JARM fingerprint with analyst-supplied host and note fields.'
    : 'Store this fingerprint in the local analyst-curated reference table with any additional context you know.';
  return `
    <details class="matches-box" open>
      <summary>Analyst Save</summary>
      <div class="action-list">
        <div class="action-row">
          <div>
            <div class="action-row-title">${escapeHtml(String(artifact.artifact_type || '').toUpperCase())}</div>
            <code>${escapeHtml(artifact.artifact_value || '')}</code>
            <div class="match-subtle">${escapeHtml(subtitle)}</div>
          </div>
          <button type="button" data-action="${artifactType === 'jarm' ? 'open-save-standalone-jarm' : 'open-save-standalone-reference'}">${escapeHtml(title)}</button>
        </div>
      </div>
    </details>
  `;
}

function renderStandaloneAnalysisResult(result) {
  if (!result?.artifact) {
    return '<div class="summary-empty">Paste a hash and analyze it to see one direct artifact view without packet context.</div>';
  }
  const artifact = result.artifact;
  const referenceMatches = result.reference_matches || [];
  const jarmMatches = result.jarm_matches || [];
  const bestReferenceMatch = referenceMatches[0];
  const bestJarmMatch = jarmMatches[0];
  const bestMatch = bestReferenceMatch || bestJarmMatch || null;
  const matchClass = bestReferenceMatch?.match_kind === 'exact' || bestJarmMatch?.match_kind === 'exact' ? 'match-note exact' : 'match-note';
  const matchText = bestMatch?.note || 'No saved match found';
  return `
    <article class="artifact-card standalone-artifact-card">
      <header class="artifact-card-header">
        <div>
          <div class="match-subtle">${escapeHtml(String(artifact.artifact_type || '').toUpperCase())}</div>
          <div class="artifact-card-title">${escapeHtml(artifact.artifact_value || '')}</div>
        </div>
        <div class="${matchClass}">${escapeHtml(matchText)}</div>
      </header>
      <div class="artifact-body">
        ${renderBreakdownGrid(artifact)}
        ${renderRawGrid(artifact)}
        ${renderStandaloneInferenceBox(artifact)}
        ${renderStandaloneMatches(result)}
        ${renderStandaloneAnalystBox(result)}
      </div>
    </article>
  `;
}

function renderAnalystBox(payload) {
  const packet = payload?.packet || {};
  const packetId = Number(packet.id);
  const state = getPacketState(packetId);
  const saveableArtifacts = (payload?.artifacts || []).filter((item) => isSaveableArtifactType(item.artifact_type));
  const destinationDomain = packet.packet_inspector?.destination_domain || extractDestinationDomain(packet.endpoint_text);
  const suggestedTargetPort = getSuggestedJarmPort(packetId, packet);
  if (!state.jarmTargetPort) state.jarmTargetPort = String(suggestedTargetPort);

  return `
    <details class="matches-box" ${state.analystOpen ? 'open' : ''} data-state-key="analystOpen">
      <summary>Analyst Save / JARM</summary>
      <div class="action-list">
        ${saveableArtifacts.map((item) => `
          <div class="action-row">
            <div>
              <div class="action-row-title">${escapeHtml(String(item.artifact_type || '').toUpperCase())}</div>
              <code>${escapeHtml(item.artifact_value || '')}</code>
            </div>
            <button type="button" data-action="open-save-artifact" data-packet-id="${packetId}" data-artifact-id="${item.id}">Save</button>
          </div>
        `).join('')}
        ${destinationDomain ? `
          <div class="action-row">
            <div>
              <div class="action-row-title">Destination Domain</div>
              <code>${escapeHtml(destinationDomain)}</code>
              <div class="inline-field-row">
                <label class="inline-label" for="jarm-target-port-${packetId}">JARM port</label>
                <input id="jarm-target-port-${packetId}" class="inline-port-input" data-action="set-jarm-target-port" data-packet-id="${packetId}" type="number" min="1" max="65535" value="${escapeAttribute(state.jarmTargetPort || suggestedTargetPort)}">
              </div>
              <div class="match-subtle">JARM runs active TLS probing against ${escapeHtml(destinationDomain)} on port ${escapeHtml(state.jarmTargetPort || suggestedTargetPort)}.</div>
            </div>
            <button type="button" data-action="run-jarm" data-packet-id="${packetId}" ${state.jarmLoading ? 'disabled' : ''}>${state.jarmLoading ? 'Running JARM...' : 'Try JARM Enrichment'}</button>
          </div>
        ` : ''}
        ${state.jarmError ? `
          <div class="action-row">
            <div>
              <div class="action-row-title">JARM Error</div>
              <div>${escapeHtml(state.jarmError)}</div>
            </div>
          </div>
        ` : ''}
        ${state.jarmResult ? renderJarmResultBox(packetId, state.jarmResult) : ''}
      </div>
    </details>
  `;
}

function renderJarmResultBox(packetId, jarmResult) {
  const savedStatus = jarmResult.savedStatus;
  const noMeaningfulValues = isAllZeroJarm(jarmResult.jarm_fingerprint);
  return `
    <div class="action-row">
      <div>
        <div class="action-row-title">JARM Result</div>
        <div class="jarm-match-value">${escapeHtml(jarmResult.jarm_fingerprint || '')}</div>
        <div class="match-subtle">${escapeHtml(jarmResult.target_host || '')}${jarmResult.resolved_ip ? ` -> ${escapeHtml(jarmResult.resolved_ip)}` : ''}</div>
        ${noMeaningfulValues ? '<div class="status-callout status-callout-warning">No meaningful TLS values returned.</div>' : ''}
      </div>
      <div class="action-button-group">
        <button type="button" data-action="open-save-jarm" data-packet-id="${packetId}">Save JARM</button>
      </div>
    </div>
    ${savedStatus ? `<div class="drawer-status">${escapeHtml(savedStatus)}</div>` : ''}
    ${renderJarmNotesBox(packetId, jarmResult.notes || [])}
    ${renderJarmMatchesBox(packetId, jarmResult.matches || [])}
  `;
}

function renderJarmNotesBox(packetId, notes) {
  if (!notes.length) return '';
  const state = getPacketState(packetId);
  return `
    <details class="matches-box" ${state.jarmNotesOpen ? 'open' : ''} data-state-key="jarmNotesOpen">
      <summary>JARM Notes</summary>
      <div class="jarm-note-list">
        ${notes.map((note) => `<div class="jarm-note-item">${escapeHtml(note)}</div>`).join('')}
      </div>
    </details>
  `;
}

function renderJarmMatchesBox(packetId, matches) {
  if (!matches.length) return '';
  const state = getPacketState(packetId);
  return `
    <details class="matches-box" ${state.jarmMatchesOpen ? 'open' : ''} data-state-key="jarmMatchesOpen">
      <summary>JARM Matches</summary>
      <div class="jarm-match-list">
        ${matches.map((match) => `
          <div class="jarm-match-card">
            <div class="action-row-title">${escapeHtml(match.note || 'JARM match')}</div>
            <div class="jarm-match-value">${escapeHtml(match.saved?.jarm_fingerprint || '')}</div>
            <div class="match-subtle">${escapeHtml(match.saved?.target_host || '')}${match.saved?.target_ip ? ` / ${escapeHtml(match.saved.target_ip)}` : ''}</div>
            ${match.saved?.destination_domain ? `<div class="match-subtle">domain: ${escapeHtml(match.saved.destination_domain)}</div>` : ''}
            ${match.saved?.analyst_note ? `<div class="match-subtle">note: ${escapeHtml(match.saved.analyst_note)}</div>` : ''}
          </div>
        `).join('')}
      </div>
    </details>
  `;
}

function wirePacketDetailActions(packetId) {
  const detailRow = document.getElementById(`detail-row-${packetId}`);
  if (!detailRow) return;
  detailRow.querySelectorAll('details[data-state-key]').forEach((details) => {
    details.addEventListener('toggle', () => {
      const state = getPacketState(packetId);
      const key = details.dataset.stateKey;
      if (key) state[key] = details.open;
    });
  });
  detailRow.querySelectorAll('.layer-node[data-layer-node-key]').forEach((details) => {
    details.addEventListener('toggle', () => {
      const state = getPacketState(packetId);
      const key = details.dataset.layerNodeKey;
      if (!key) return;
      if (!state.layerNodeState) state.layerNodeState = {};
      state.layerNodeState[key] = details.open;
    });
  });
  detailRow.querySelectorAll('[data-action="open-save-artifact"]').forEach((button) => {
    button.addEventListener('click', () => openArtifactSaveDrawer(packetId, Number(button.dataset.artifactId)));
  });
  detailRow.querySelectorAll('[data-action="run-jarm"]').forEach((button) => {
    button.addEventListener('click', () => runJarmForPacket(packetId));
  });
  detailRow.querySelectorAll('[data-action="open-save-jarm"]').forEach((button) => {
    button.addEventListener('click', () => openJarmSaveDrawer(packetId));
  });
  detailRow.querySelectorAll('[data-action="toggle-shodan-key"]').forEach((button) => {
    button.addEventListener('click', () => {
      const state = getPacketState(packetId);
      state.shodanKeyEditorOpen = !state.shodanKeyEditorOpen;
      renderDetailRow(packetId);
    });
  });
  detailRow.querySelectorAll('[data-action="collapse-shodan-key"]').forEach((button) => {
    button.addEventListener('click', () => {
      const state = getPacketState(packetId);
      state.shodanKeyEditorOpen = false;
      renderDetailRow(packetId);
    });
  });
  detailRow.querySelectorAll('[data-action="run-shodan"]').forEach((button) => {
    button.addEventListener('click', () => runShodanForPacket(packetId));
  });
  detailRow.querySelectorAll('[data-action="set-jarm-target-port"]').forEach((input) => {
    input.addEventListener('input', () => {
      const state = getPacketState(packetId);
      state.jarmTargetPort = String(input.value || '').trim();
    });
  });
  detailRow.querySelectorAll('[data-action="open-citation"]').forEach((button) => {
    button.addEventListener('click', () => openCitationDrawer(Number(button.dataset.sourceId)));
  });
  detailRow.querySelectorAll('#shodan-key-form').forEach((form) => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      await submitShodanKeyForm(packetId, form);
    });
  });
}

function openArtifactSaveDrawer(packetId, artifactId) {
  const payload = getPacketDetailPayload(packetId);
  const artifact = getArtifactById(packetId, artifactId);
  if (!payload || !artifact) {
    logLine(`Unable to open save drawer for packet ${packetId}, artifact ${artifactId}.`);
    return;
  }
  const packet = payload.packet || {};
  const inspector = packet.packet_inspector || {};
  const state = getPacketState(packetId);
  const relatedValues = getRelatedArtifactValues(packetId, artifact);
  const destinationDomain = inspector.destination_domain || extractDestinationDomain(packet.endpoint_text);
  const artifactType = String(artifact.artifact_type || '').trim().toLowerCase();
  const passiveUserAgent = inspector.user_agent || '';
  const shodanIssuer = state.shodanResult?.host_lookup?.certificate?.issuer || '';
  const certificateAuthority = inspector.certificate_authority || shodanIssuer;
  const html = `
    <form id="artifact-save-form" class="drawer-form">
      <div class="drawer-status">
        Saving a local analyst-curated reference row for packet ${escapeHtml(packet.packet_number || packetId)}.
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="save-artifact-type">Artifact Type</label>
          <input id="save-artifact-type" name="artifact_type" type="text" value="${escapeAttribute(artifactType)}" readonly>
        </div>
        <div class="drawer-field">
          <label for="save-artifact-value">Artifact Value</label>
          <input id="save-artifact-value" name="artifact_value" type="text" value="${escapeAttribute(artifact.artifact_value || '')}">
        </div>
        <div class="drawer-field">
          <label for="save-destination-domain">Destination Domain</label>
          <input id="save-destination-domain" name="destination_domain" type="text" value="${escapeAttribute(destinationDomain)}">
        </div>
        <div class="drawer-field">
          <label for="save-application">Application</label>
          <input id="save-application" name="application" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="save-library-name">Library</label>
          <input id="save-library-name" name="library_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="save-device-name">Device</label>
          <input id="save-device-name" name="device_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="save-os-name">OS</label>
          <input id="save-os-name" name="os_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="save-user-agent">User Agent</label>
          <input id="save-user-agent" name="user_agent_string" type="text" value="${escapeAttribute(passiveUserAgent)}">
        </div>
        <div class="drawer-field">
          <label for="save-ca">Certificate Authority</label>
          <input id="save-ca" name="certificate_authority" type="text" value="${escapeAttribute(certificateAuthority)}">
        </div>
      </div>
      <div class="drawer-field">
        <label for="save-analyst-note">Analyst Note</label>
        <textarea id="save-analyst-note" name="analyst_note" placeholder="Add any local context worth preserving."></textarea>
      </div>
      <div class="drawer-helper">
        Related packet values: ${escapeHtml(formatRelatedValues(relatedValues))}
      </div>
      <div id="artifact-save-status" class="drawer-helper"></div>
      <div class="action-button-group">
        <button type="submit">Save Reference</button>
        <button type="button" data-drawer-close="true">Cancel</button>
      </div>
    </form>
  `;

  openDrawer({
    kicker: 'Analyst Save',
    title: `Save ${String(artifact.artifact_type || '').toUpperCase()}`,
    bodyHtml: html,
    onOpen: (body) => {
      const form = body.querySelector('#artifact-save-form');
      body.querySelector('[data-drawer-close="true"]')?.addEventListener('click', closeDrawer);
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitArtifactSaveForm(packetId, artifactId, artifact, form);
      });
    },
  });
}

async function submitArtifactSaveForm(packetId, artifactId, artifact, form) {
  const status = document.getElementById('artifact-save-status');
  const relatedValues = getRelatedArtifactValues(packetId, artifact);
  const payload = Object.fromEntries(new FormData(form).entries());
  Object.assign(payload, relatedValues);
  payload.artifact_value = String(payload.artifact_value || artifact.artifact_value || '').trim();
  if (status) status.textContent = 'Saving reference...';
  try {
    const response = await fetch(`/api/artifacts/${artifactId}/save-reference`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Reference save failed');
    const verb = result.inserted ? 'Saved' : 'Reused existing';
    logLine(`${verb} ${String(artifact.artifact_type || '').toUpperCase()} analyst reference for packet ${packetId}.`);
    closeDrawer();
    renderDetailRow(packetId);
  } catch (error) {
    if (status) status.textContent = error.message;
    logLine(`Reference save failed for packet ${packetId}: ${error.message}`);
  }
}

async function runJarmForPacket(packetId) {
  const payload = getPacketDetailPayload(packetId);
  if (!payload) return;
  const packet = payload.packet || {};
  const state = getPacketState(packetId);
  const destinationDomain = packet.packet_inspector?.destination_domain || extractDestinationDomain(packet.endpoint_text);
  const targetPort = getSuggestedJarmPort(packetId, packet);
  if (!destinationDomain) {
    state.jarmError = 'No destination domain was available for JARM enrichment.';
    rerenderPacketDetailPreservingPosition(packetId);
    return;
  }
  state.jarmLoading = true;
  state.jarmError = '';
  state.analystOpen = true;
  state.jarmTargetPort = String(targetPort);
  rerenderPacketDetailPreservingPosition(packetId);
  try {
    const response = await fetch(`/api/packets/${packetId}/jarm-enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_host: destinationDomain,
        target_port: targetPort,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'JARM enrichment failed');
    result.destination_domain = destinationDomain;
    result.target_port = targetPort;
    state.jarmResult = result;
    state.jarmError = '';
    logLine(`JARM enrichment completed for packet ${packetId} against ${destinationDomain}:${targetPort}.`);
  } catch (error) {
    state.jarmResult = null;
    state.jarmError = error.message;
    logLine(`JARM enrichment failed for packet ${packetId}: ${error.message}`);
  } finally {
    state.jarmLoading = false;
    rerenderPacketDetailPreservingPosition(packetId);
  }
}

async function submitShodanKeyForm(packetId, form) {
  const state = getPacketState(packetId);
  const payload = Object.fromEntries(new FormData(form).entries());
  state.shodanKeyStatus = 'Saving and testing Shodan key...';
  state.shodanError = '';
  rerenderPacketDetailPreservingPosition(packetId);
  try {
    const response = await fetch('/api/shodan/configure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Shodan key setup failed');
    appRuntime.shodanConfigured = true;
    state.shodanKeyStatus = `Shodan key accepted. Query credits: ${result.info?.query_credits ?? 'n/a'}.`;
    state.shodanKeyEditorOpen = true;
    logLine(`Shodan key updated for packet ${packetId}.`);
  } catch (error) {
    state.shodanError = error.message;
    state.shodanKeyStatus = '';
    logLine(`Shodan key update failed for packet ${packetId}: ${error.message}`);
  }
  rerenderPacketDetailPreservingPosition(packetId);
}

async function runShodanForPacket(packetId) {
  const payload = getPacketDetailPayload(packetId);
  const packet = payload?.packet || {};
  const inspector = packet.packet_inspector || {};
  const shodanTarget = getShodanTarget(packet, inspector);
  if (!shodanTarget.enabled) return;
  const state = getPacketState(packetId);
  state.shodanLoading = true;
  state.shodanError = '';
  state.shodanKeyStatus = '';
  rerenderPacketDetailPreservingPosition(packetId);
  try {
    const response = await fetch(`/api/packets/${packetId}/shodan-enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ force_refresh: false }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Shodan enrichment failed');
    state.shodanResult = result;
    logLine(`Shodan enrichment completed for packet ${packetId}.`);
  } catch (error) {
    state.shodanResult = null;
    state.shodanError = error.message;
    logLine(`Shodan enrichment failed for packet ${packetId}: ${error.message}`);
  } finally {
    state.shodanLoading = false;
    rerenderPacketDetailPreservingPosition(packetId);
  }
}

function openJarmSaveDrawer(packetId) {
  const payload = getPacketDetailPayload(packetId);
  const packet = payload?.packet || {};
  const state = getPacketState(packetId);
  const jarmResult = state.jarmResult;
  if (!payload || !jarmResult) {
    logLine(`Unable to open JARM save drawer for packet ${packetId}.`);
    return;
  }
  const html = `
    <form id="jarm-save-form" class="drawer-form">
      <div class="drawer-status">
        Save the active JARM result with the passive packet context from this row.
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="jarm-target-host">Target Host</label>
          <input id="jarm-target-host" name="target_host" type="text" value="${escapeAttribute(jarmResult.target_host || '')}">
        </div>
        <div class="drawer-field">
          <label for="jarm-target-ip">Target IP</label>
          <input id="jarm-target-ip" name="target_ip" type="text" value="${escapeAttribute(jarmResult.resolved_ip || packet.dst_ip || '')}">
        </div>
        <div class="drawer-field">
          <label for="jarm-target-port">Target Port</label>
          <input id="jarm-target-port" name="target_port" type="text" value="${escapeAttribute(jarmResult.target_port || packet.dst_port || 443)}">
        </div>
        <div class="drawer-field">
          <label for="jarm-destination-domain">Destination Domain</label>
          <input id="jarm-destination-domain" name="destination_domain" type="text" value="${escapeAttribute(jarmResult.destination_domain || extractDestinationDomain(packet.endpoint_text) || '')}">
        </div>
        <div class="drawer-field">
          <label for="jarm-fingerprint">JARM Fingerprint</label>
          <input id="jarm-fingerprint" name="jarm_fingerprint" type="text" value="${escapeAttribute(jarmResult.jarm_fingerprint || '')}">
        </div>
      </div>
      <div class="drawer-field">
        <label for="jarm-note">Analyst Note</label>
        <textarea id="jarm-note" name="analyst_note" placeholder="Add any likely C2 or hosting context."></textarea>
      </div>
      <div id="jarm-save-status" class="drawer-helper"></div>
      <div class="action-button-group">
        <button type="submit">Save JARM</button>
        <button type="button" data-drawer-close="true">Cancel</button>
      </div>
    </form>
  `;

  openDrawer({
    kicker: 'JARM Save',
    title: 'Save JARM Result',
    bodyHtml: html,
    onOpen: (body) => {
      const form = body.querySelector('#jarm-save-form');
      body.querySelector('[data-drawer-close="true"]')?.addEventListener('click', closeDrawer);
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitJarmSaveForm(packetId, form);
      });
    },
  });
}

async function submitJarmSaveForm(packetId, form) {
  const status = document.getElementById('jarm-save-status');
  const state = getPacketState(packetId);
  const payload = Object.fromEntries(new FormData(form).entries());
  payload.jarm_raw = state.jarmResult?.jarm_raw || '';
  if (status) status.textContent = 'Saving JARM...';
  try {
    const response = await fetch(`/api/packets/${packetId}/save-jarm`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'JARM save failed');
    const savedStatus = result.inserted ? 'Saved JARM fingerprint.' : 'JARM fingerprint already existed for this target.';
    state.jarmResult = {
      ...(state.jarmResult || {}),
      ...payload,
      resolved_ip: payload.target_ip || state.jarmResult?.resolved_ip || '',
      matches: result.matches || [],
      savedStatus,
    };
    closeDrawer();
    renderDetailRow(packetId);
    logLine(`Saved JARM result for packet ${packetId}.`);
  } catch (error) {
    if (status) status.textContent = error.message;
    logLine(`JARM save failed for packet ${packetId}: ${error.message}`);
  }
}

function formatRelatedValues(relatedValues) {
  const ordered = ['ja4', 'ja4s', 'ja4h', 'ja4x', 'ja4t', 'ja4ts'];
  const entries = ordered
    .filter((key) => relatedValues[key])
    .map((key) => `${key}=${relatedValues[key]}`);
  return entries.length ? entries.join(', ') : 'No related JA4-family values were available on this row.';
}

function setStandaloneStatus(text) {
  const chip = document.getElementById('standalone-status');
  if (chip) chip.textContent = text;
}

function renderStandaloneAnalysisToDom(result = null) {
  standaloneAnalysisResult = result;
  const shell = document.getElementById('standalone-analysis-result');
  if (!shell) return;
  shell.innerHTML = renderStandaloneAnalysisResult(result);
  shell.querySelectorAll('[data-action="open-citation"]').forEach((button) => {
    button.addEventListener('click', () => openCitationDrawer(Number(button.dataset.sourceId)));
  });
  shell.querySelectorAll('[data-action="open-save-standalone-reference"]').forEach((button) => {
    button.addEventListener('click', openStandaloneReferenceSaveDrawer);
  });
  shell.querySelectorAll('[data-action="open-save-standalone-jarm"]').forEach((button) => {
    button.addEventListener('click', openStandaloneJarmSaveDrawer);
  });
}

async function analyzeStandaloneHash() {
  const typeEl = document.getElementById('standalone-hash-type');
  const valueEl = document.getElementById('standalone-hash-value');
  const artifactType = String(typeEl?.value || '').trim().toLowerCase();
  const artifactValue = String(valueEl?.value || '').trim();
  if (!artifactValue) {
    setStandaloneStatus('Missing hash');
    logLine('Paste a hash before running direct analysis.');
    return;
  }
  setStandaloneStatus('Analyzing hash...');
  try {
    const response = await fetch('/api/hash-analysis', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        artifact_type: artifactType,
        artifact_value: artifactValue,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Hash analysis failed');
    renderStandaloneAnalysisToDom(result);
    setStandaloneStatus('Hash analyzed');
    logLine(`Analyzed standalone ${artifactType.toUpperCase()} value.`);
  } catch (error) {
    renderStandaloneAnalysisToDom(null);
    setStandaloneStatus('Analysis failed');
    logLine(`Hash analysis failed: ${error.message}`);
    const shell = document.getElementById('standalone-analysis-result');
    if (shell) shell.innerHTML = `<div class="summary-empty">${escapeHtml(error.message)}</div>`;
  }
}

function openStandaloneReferenceSaveDrawer() {
  const artifact = standaloneAnalysisResult?.artifact;
  if (!artifact) return;
  const artifactType = String(artifact.artifact_type || '').trim().toLowerCase();
  const relatedDefaults = {
    ja4: artifactType === 'ja4' ? artifact.artifact_value || '' : '',
    ja4s: artifactType === 'ja4s' ? artifact.artifact_value || '' : '',
    ja4h: artifactType === 'ja4h' ? artifact.artifact_value || '' : '',
    ja4x: artifactType === 'ja4x' ? artifact.artifact_value || '' : '',
    ja4t: artifactType === 'ja4t' || artifactType === 'ja4ts' ? artifact.artifact_value || '' : '',
  };
  const html = `
    <form id="standalone-reference-save-form" class="drawer-form">
      <div class="drawer-status">
        Save this hash directly to the analyst-curated reference table.
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="standalone-save-artifact-type">Artifact Type</label>
          <input id="standalone-save-artifact-type" name="artifact_type" type="text" value="${escapeAttribute(artifactType)}" readonly>
        </div>
        <div class="drawer-field">
          <label for="standalone-save-artifact-value">Artifact Value</label>
          <input id="standalone-save-artifact-value" name="artifact_value" type="text" value="${escapeAttribute(artifact.artifact_value || '')}">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-destination-domain">Destination Domain</label>
          <input id="standalone-save-destination-domain" name="destination_domain" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-application">Application</label>
          <input id="standalone-save-application" name="application" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-library-name">Library</label>
          <input id="standalone-save-library-name" name="library_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-device-name">Device</label>
          <input id="standalone-save-device-name" name="device_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-os-name">OS</label>
          <input id="standalone-save-os-name" name="os_name" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-user-agent">User Agent</label>
          <input id="standalone-save-user-agent" name="user_agent_string" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-ca">Certificate Authority</label>
          <input id="standalone-save-ca" name="certificate_authority" type="text" value="">
        </div>
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="standalone-save-ja4">Related JA4</label>
          <input id="standalone-save-ja4" name="ja4" type="text" value="${escapeAttribute(relatedDefaults.ja4)}">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-ja4s">Related JA4S</label>
          <input id="standalone-save-ja4s" name="ja4s" type="text" value="${escapeAttribute(relatedDefaults.ja4s)}">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-ja4h">Related JA4H</label>
          <input id="standalone-save-ja4h" name="ja4h" type="text" value="${escapeAttribute(relatedDefaults.ja4h)}">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-ja4x">Related JA4X</label>
          <input id="standalone-save-ja4x" name="ja4x" type="text" value="${escapeAttribute(relatedDefaults.ja4x)}">
        </div>
        <div class="drawer-field">
          <label for="standalone-save-ja4t">Related JA4T</label>
          <input id="standalone-save-ja4t" name="ja4t" type="text" value="${escapeAttribute(relatedDefaults.ja4t)}">
        </div>
      </div>
      <div class="drawer-field">
        <label for="standalone-save-analyst-note">Analyst Note</label>
        <textarea id="standalone-save-analyst-note" name="analyst_note" placeholder="Add any local knowledge worth preserving for this hash."></textarea>
      </div>
      <div id="standalone-reference-save-status" class="drawer-helper"></div>
      <div class="action-button-group">
        <button type="submit">Save Reference</button>
        <button type="button" data-drawer-close="true">Cancel</button>
      </div>
    </form>
  `;
  openDrawer({
    kicker: 'Analyst Save',
    title: `Save ${String(artifact.artifact_type || '').toUpperCase()}`,
    bodyHtml: html,
    onOpen: (body) => {
      const form = body.querySelector('#standalone-reference-save-form');
      body.querySelector('[data-drawer-close="true"]')?.addEventListener('click', closeDrawer);
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitStandaloneReferenceSaveForm(form);
      });
    },
  });
}

async function submitStandaloneReferenceSaveForm(form) {
  const status = document.getElementById('standalone-reference-save-status');
  const payload = Object.fromEntries(new FormData(form).entries());
  if (status) status.textContent = 'Saving reference...';
  try {
    const response = await fetch('/api/references/save-standalone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Reference save failed');
    closeDrawer();
    logLine(`${result.inserted ? 'Saved' : 'Reused existing'} standalone ${String(payload.artifact_type || '').toUpperCase()} reference.`);
  } catch (error) {
    if (status) status.textContent = error.message;
    logLine(`Standalone reference save failed: ${error.message}`);
  }
}

function openStandaloneJarmSaveDrawer() {
  const artifact = standaloneAnalysisResult?.artifact;
  if (!artifact) return;
  const html = `
    <form id="standalone-jarm-save-form" class="drawer-form">
      <div class="drawer-status">
        Save this JARM fingerprint with analyst-supplied host context.
      </div>
      <div class="drawer-grid">
        <div class="drawer-field">
          <label for="standalone-jarm-target-host">Target Host</label>
          <input id="standalone-jarm-target-host" name="target_host" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-jarm-target-ip">Target IP</label>
          <input id="standalone-jarm-target-ip" name="target_ip" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-jarm-target-port">Target Port</label>
          <input id="standalone-jarm-target-port" name="target_port" type="text" value="443">
        </div>
        <div class="drawer-field">
          <label for="standalone-jarm-destination-domain">Destination Domain</label>
          <input id="standalone-jarm-destination-domain" name="destination_domain" type="text" value="">
        </div>
        <div class="drawer-field">
          <label for="standalone-jarm-fingerprint">JARM Fingerprint</label>
          <input id="standalone-jarm-fingerprint" name="jarm_fingerprint" type="text" value="${escapeAttribute(artifact.artifact_value || '')}">
        </div>
      </div>
      <div class="drawer-field">
        <label for="standalone-jarm-note">Analyst Note</label>
        <textarea id="standalone-jarm-note" name="analyst_note" placeholder="Add any likely hosting, malware, or campaign context."></textarea>
      </div>
      <div id="standalone-jarm-save-status" class="drawer-helper"></div>
      <div class="action-button-group">
        <button type="submit">Save JARM</button>
        <button type="button" data-drawer-close="true">Cancel</button>
      </div>
    </form>
  `;
  openDrawer({
    kicker: 'JARM Save',
    title: 'Save JARM Fingerprint',
    bodyHtml: html,
    onOpen: (body) => {
      const form = body.querySelector('#standalone-jarm-save-form');
      body.querySelector('[data-drawer-close="true"]')?.addEventListener('click', closeDrawer);
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        await submitStandaloneJarmSaveForm(form);
      });
    },
  });
}

async function submitStandaloneJarmSaveForm(form) {
  const status = document.getElementById('standalone-jarm-save-status');
  const payload = Object.fromEntries(new FormData(form).entries());
  if (status) status.textContent = 'Saving JARM...';
  try {
    const response = await fetch('/api/jarm/save-standalone', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'JARM save failed');
    closeDrawer();
    logLine(`${result.inserted ? 'Saved' : 'Reused existing'} standalone JARM fingerprint.`);
  } catch (error) {
    if (status) status.textContent = error.message;
    logLine(`Standalone JARM save failed: ${error.message}`);
  }
}

function isAllZeroJarm(value) {
  const text = String(value || '').trim();
  return text.length === 62 && /^0+$/.test(text);
}

function renderMatches(matches) {
  if (!matches.length) return '';
  return `
    <details class="matches-box">
      <summary>${escapeHtml(matches.length)} reference match${matches.length === 1 ? '' : 'es'}</summary>
      <div class="matches-list">
        ${matches.map((match) => `
          <article class="match-card">
            <div class="match-header">
              <div>
                <div class="match-title">${escapeHtml(match.reference.application || match.reference.os_name || match.reference.device_name || 'historical reference')}</div>
                <div class="match-subtle">${escapeHtml(match.note)}</div>
              </div>
              <div class="match-subtle">${escapeHtml((match.matched_sections || []).join(', ') || 'full fingerprint')}</div>
            </div>
            <div class="kv-grid">
              ${renderMatchedFieldGrid(match.matched_fields || [])}
              ${renderReferenceField('library', match.reference.library_name)}
              ${renderReferenceField('device', match.reference.device_name)}
              ${renderReferenceField('os', match.reference.os_name)}
              ${renderReferenceField('user agent', match.reference.user_agent_string)}
              ${renderReferenceField('ja4', match.reference.fingerprint_value)}
              ${renderReferenceField('ja4s', match.reference.ja4s_fingerprint)}
              ${renderReferenceField('ja4h', match.reference.ja4h_fingerprint)}
              ${renderReferenceField('ja4x', match.reference.ja4x_fingerprint)}
              ${renderReferenceField('ja4t', match.reference.ja4t_fingerprint)}
            </div>
          </article>
        `).join('')}
      </div>
    </details>
  `;
}

function renderMatchedFieldGrid(fields) {
  if (!fields.length) return '';
  return fields.map((field) => `
    <div class="kv-item match-focus-item">
      <span class="kv-label">matched field</span>
      <span class="kv-value">${escapeHtml(field.label)} = ${escapeHtml(field.value)}</span>
    </div>
  `).join('');
}

function renderReferenceField(label, value) {
  if (!value) return '';
  return `
    <div class="kv-item">
      <span class="kv-label">${escapeHtml(label)}</span>
      <span class="kv-value">${escapeHtml(value)}</span>
    </div>
  `;
}

function explainArtifactPart(artifact, label, value) {
  const artifactType = (artifact?.artifact_type || '').toLowerCase();
  const stringValue = String(value ?? '');
  const upperLabel = label.toUpperCase();

  const generic = { displayValue: stringValue, inlineHint: '', note: '' };
  const combine = (inlineHint = '', note = '') => ({
    displayValue: stringValue,
    inlineHint,
    note,
  });

  if (artifactType === 'ja4h') {
    if (label === 'method') return combine(mapHttpMethodCode(stringValue), 'first two method characters');
    if (label === 'http_version') return combine(mapHttpVersionCode(stringValue), 'two-character HTTP version code.');
    if (label === 'cookie_flag') return combine(stringValue === 'c' ? 'cookies present' : stringValue === 'n' ? 'no Cookie header' : '', '');
    if (label === 'referer_flag') return combine(stringValue === 'r' ? 'Referer present' : stringValue === 'n' ? 'no Referer header' : '', '');
    if (label === 'header_count') return combine(`${parseInteger(stringValue) ?? 0} headers`, 'Cookie and Referer excluded.');
    if (label === 'accept_language') return combine(mapAcceptLanguageCode(stringValue), 'normalized primary Accept-Language value');
    if (label === 'ja4h_a') return combine('', 'HTTP request shape');
    if (label === 'ja4h_b') return combine('', 'hash of ordered header names');
    if (label === 'ja4h_c') return combine('', 'hash of sorted cookie names');
    if (label === 'ja4h_d') return combine('', 'hash of sorted cookie name=value pairs');
  }

  if (artifactType === 'ja4') {
    if (label === 'protocol') return combine(mapJa4Protocol(stringValue), '');
    if (label === 'tls_version') return combine(mapTlsVersionCode(stringValue), '');
    if (label === 'sni_flag') return combine(stringValue === 'd' ? 'SNI present' : stringValue === 'i' ? 'no SNI' : '', 'named host flag');
    if (label === 'cipher_count') return combine(`${parseInteger(stringValue) ?? 0} ciphers`, 'GREASE ignored.');
    if (label === 'extension_count') return combine(`${parseInteger(stringValue) ?? 0} extensions`, 'GREASE ignored.');
    if (label === 'alpn') return combine(mapAlpnCode(stringValue), 'first and last chars of first ALPN token');
    if (label === 'ja4_a') return combine('', 'TLS client shape');
    if (label === 'ja4_b') return combine('', 'hash of sorted cipher suites');
    if (label === 'ja4_c') return combine('', 'hash of sorted extensions and sigalgs');
  }

  if (artifactType === 'ja4s') {
    if (label === 'protocol') return combine(mapJa4Protocol(stringValue), '');
    if (label === 'tls_version') return combine(mapTlsVersionCode(stringValue), '');
    if (label === 'extension_count') return combine(`${parseInteger(stringValue) ?? 0} extensions`, 'server extension count');
    if (label === 'alpn') return combine(mapAlpnCode(stringValue), 'negotiated ALPN code');
    if (label === 'ja4s_a') return combine('', 'TLS server response shape');
    if (label === 'ja4s_b') return combine('', 'selected cipher suite code');
    if (label === 'ja4s_c') return combine('', 'hash of server extensions');
  }

  if (artifactType === 'ja4t' || artifactType === 'ja4ts') {
    if (label === 'window_size') {
      const scale = parseInteger(artifact?.parts?.window_scale) ?? 0;
      const effective = computeScaledWindow(stringValue, scale);
      return combine(scale > 0 && effective ? `scales to ${formatBytes(effective)}` : '', 'advertised receive window');
    }
    if (label === 'tcp_options') return combine(describeTcpOptions(stringValue), 'wire-order TCP options');
    if (label === 'mss') return combine(describeMssValue(stringValue), '');
    if (label === 'window_scale') {
      const scale = parseInteger(stringValue);
      return combine(scale === null ? '' : `2^${scale} = ${formatNumber(2 ** scale)}`, 'window scale multiplier');
    }
  }

  if (artifactType === 'ja4x') {
    if (label === 'ja4x_a') return combine('', 'hash of issuer RDN OID sequence');
    if (label === 'ja4x_b') return combine('', 'hash of subject RDN OID sequence');
    if (label === 'ja4x_c') return combine('', 'hash of certificate extension OID sequence');
  }

  if (artifactType === 'ja4l' || artifactType === 'ja4ls') {
    if (label === 'direction') return combine(stringValue === 'client' ? 'client to server' : stringValue === 'server' ? 'server to client' : '', 'handshake view');
    if (label === 'latency_microseconds') return combine('', 'SYN to SYN-ACK span in microseconds');
    if (label === 'observed_ttl') return combine(describeObservedTtl(stringValue), '');
  }

  if (artifactType === 'ja4ssh') {
    if (label === 'ja4ssh_a') return combine('', 'modal encrypted payload sizes, client/server');
    if (label === 'ja4ssh_b') return combine('', 'SSH payload counts, client/server');
    if (label === 'ja4ssh_c') return combine('', 'bare ACK counts, client/server');
  }

  if (artifactType === 'jarm') {
    if (label === 'jarm_first_30') return combine('', 'TLS version and cipher behavior across the 10 JARM probes');
    if (label === 'jarm_last_32') return combine('', 'truncated hash of aggregated extension behavior');
  }

  if (artifactType === 'hassh' || artifactType === 'hassh_server' || artifactType === 'ja3' || artifactType === 'ja3s') {
    if (label === 'hash') return combine('', `${upperLabel} fingerprint hash`);
  }

  return generic;
}

function inferArtifact(packetId, artifact) {
  const artifactType = (artifact?.artifact_type || '').toLowerCase();
  const parts = artifact?.parts || {};
  const notes = [];
  const pushNote = (text, sourceId, kind = 'inference') => {
    if (!text) return;
    notes.push({ text, sourceId, kind });
  };
  const packetState = Number.isFinite(packetId) ? getPacketState(packetId) : null;
  const packetPayload = getPacketDetailPayload(packetId);
  const packet = packetPayload?.packet || {};
  const inspector = packet.packet_inspector || {};
  const relatedArtifactValues = getRelatedArtifactValues(packetId, artifact);
  const shodanHostLookup = packetState?.shodanResult?.host_lookup || null;
  const shodanPrimaryIp = String(packetState?.shodanResult?.primary_ip || '').trim();
  const shodanOs = String(shodanHostLookup?.operating_system || '').trim();
  const shodanTechnologies = Array.isArray(shodanHostLookup?.technologies)
    ? shodanHostLookup.technologies.filter(Boolean)
    : [];
  const shodanDomains = Array.isArray(shodanHostLookup?.domains) ? shodanHostLookup.domains.filter(Boolean) : [];
  const shodanHostnames = Array.isArray(shodanHostLookup?.hostnames) ? shodanHostLookup.hostnames.filter(Boolean) : [];
  const shodanCertificate = shodanHostLookup?.certificate || {};
  const serverSideArtifact = isServerSideArtifactType(artifactType);
  const passiveUserAgent = String(inspector.user_agent || '').trim();
  const passiveDestinationDomain = String(inspector.destination_domain || '').trim().toLowerCase();
  const passiveCertificateAuthority = String(inspector.certificate_authority || '').trim();
  const passiveCertificateSubject = String(inspector.certificate_subject || '').trim();
  const jarmResult = packetState?.jarmResult || null;

  if (artifactType === 'ja4h') {
    if (parts.cookie_flag === 'c') pushNote('Cookie flag is set, so the request carried session or state data.', 1);
    if (parts.referer_flag === 'r') pushNote('Referer flag is set, so the request likely came from a linked page or redirect flow.', 1);
    const headerCount = parseInteger(parts.header_count);
    if (headerCount !== null && headerCount <= 4) pushNote('The non-cookie header count is sparse, which is common in simple clients, APIs, or scanners.', 1);
    if (headerCount !== null && headerCount >= 8) pushNote('The non-cookie header count is relatively rich, which is more browser-like than minimal tooling.', 1);
    if (parts.http_version === '11' && headerCount !== null) {
      pushNote('HTTP/1.1 defaults to persistent connections, and requests normally carry Host, so a low header count here usually means a compact client rather than a truly minimal wire image.', 8);
    }
    const language = mapAcceptLanguageCode(parts.accept_language);
    if (language && language !== 'not advertised') pushNote(`Primary Accept-Language normalizes to ${language}.`, 1);
    if (parts.method === 'co') {
      pushNote('CONNECT is a tunneling method, so this request should be read with destination and proxy context before treating it like ordinary web retrieval.', 8, 'conclusion');
    }
    if (parts.method === 'ge' && parts.http_version === '11' && parts.cookie_flag !== 'c' && parts.referer_flag !== 'r' && headerCount !== null && headerCount <= 4) {
      pushNote('This is an HTTP/1.1 GET, but the sparse header shape and lack of cookie or referer context fit a direct fetch or tooling-style retrieval better than a click-driven browser navigation.', 8, 'conclusion');
    }
    if (passiveUserAgent && headerCount !== null && headerCount <= 4) {
      pushNote('A User-Agent string is present, but the surrounding header shape is still sparse. Treat the claimed client identity as a hint, not as proof of a full browser session.', 8, 'conclusion');
    }
    if (passiveUserAgent && headerCount !== null && headerCount >= 8) {
      pushNote(`Packet context includes a User-Agent and a richer header shape, so this HTTP request is more consistent with an interactive client than with minimal tooling alone.`, 1, 'conclusion');
    }
    if (passiveUserAgent && parts.cookie_flag === 'c' && parts.referer_flag === 'r' && headerCount !== null && headerCount >= 8) {
      pushNote('User-Agent, cookies, referer, and a richer header set all point in the same direction, so this request shape is more consistent with a browser session than with sparse scripted traffic.', 1, 'conclusion');
    }
  }

  if (artifactType === 'ja4') {
    const versionInference = inferTlsVersionSemantics(parts.tls_version);
    if (versionInference) pushNote(versionInference, 1);
    if (parts.sni_flag === 'd') pushNote('SNI is present, so this handshake was aimed at a named host rather than a bare IP.', 1);
    if (parts.sni_flag === 'i') pushNote('SNI is absent, which often means a direct IP target, ECH-adjacent hiding, or a non-browser client.', 1);
    const alpnInference = inferAlpnSemantics(parts.alpn, parts.protocol);
    if (alpnInference) pushNote(alpnInference, 1);
    if (parts.tls_version === '13') {
      pushNote('For TLS 1.3, passive analysis usually stays in the metadata lane. JA4, ALPN, SNI, and certificate context often remain more realistic than payload decryption.', 1);
    }
    if (parts.sni_flag === 'd' && passiveDestinationDomain) {
      pushNote(`SNI is present and packet context exposes the destination domain ${passiveDestinationDomain}, so named-host attribution is stronger than IP-only attribution here.`, 1, 'conclusion');
    }
    if (parts.sni_flag === 'i' && !passiveDestinationDomain) {
      pushNote('No SNI and no higher-layer destination domain were available in this packet, so host attribution will lean more on IP, certificate, and external-enrichment context.', 1, 'conclusion');
    }
  }

  if (artifactType === 'ja4s') {
    const versionInference = inferTlsVersionSemantics(parts.tls_version);
    if (versionInference) pushNote(versionInference, 1);
    const alpnInference = inferAlpnSemantics(parts.alpn, parts.protocol);
    if (alpnInference) pushNote(alpnInference, 1);
    if (parts.alpn === '00') pushNote('No ALPN was negotiated. That often points to non-HTTP TLS, older HTTPS stacks, or application protocols that do not use ALPN.', 1);
    if (parts.tls_version === '12') {
      pushNote('If you ever pursue TLS decryption in Zeek, support is narrow and environment-dependent. TLS 1.2 is the only version in that Zeek feature path, but fingerprinting and cert metadata remain the dependable passive baseline.', 1);
    }
    if (relatedArtifactValues.ja3s && shodanCertificate.ja3s && relatedArtifactValues.ja3s === shodanCertificate.ja3s) {
      pushNote('Passive JA3S from this packet matches the JA3S exposed in Shodan host data, which reinforces that the observed server TLS profile lines up with the enriched host record.', 6, 'conclusion');
    }
  }

  if (artifactType === 'ja4t' || artifactType === 'ja4ts') {
    const mss = parseInteger(parts.mss);
    const windowSize = parseInteger(parts.window_size);
    const scale = parseInteger(parts.window_scale) ?? 0;
    const effectiveWindow = computeScaledWindow(windowSize, scale);
    if (effectiveWindow) pushNote(`With window scale ${scale}, the effective advertised receive window is ${formatBytes(effectiveWindow)}.`, 10);
    if (effectiveWindow) {
      pushNote('The advertised receive window is only one throughput bound. Bytes in flight and the sender congestion window still limit how much data can actually move.', 19);
    }
    if (mss) {
      if (mss === 1460) {
        pushNote('MSS 1460 is the common Ethernet-path value for MTU 1500 without extra tunnel overhead.', 11);
      } else if (mss < 1460) {
        pushNote(`MSS ${mss} is below 1460, which usually means reduced path MTU from VPN, PPPoE, tunneling, proxy overhead, or another non-1500 path constraint.`, 11);
      } else if (mss > 1460) {
        pushNote(`MSS ${mss} is above the usual Ethernet value, which points to jumbo or otherwise larger path MTU assumptions.`, 11);
      }
    }
    if (windowSize && mss) {
      if (windowSize % mss === 0) {
        pushNote(`The unscaled window is an even ${formatNumber(windowSize / mss)} x MSS, which is a classic stack-tuned receive window pattern.`, 9);
      } else {
        let note = 'The unscaled window is not an even multiple of MSS.';
        if (effectiveWindow && effectiveWindow % mss === 0) {
          note += ` After applying scale, the effective window is ${formatNumber(effectiveWindow / mss)} x MSS.`;
        } else {
          note += ' That can happen with receive-buffer autotuning, MSS clamping on only part of the path, proxy/VPN mediation, or stack-specific sizing rather than a simple segment multiple.';
        }
        pushNote(note, 9);
      }
    }
    const options = parseTcpOptions(parts.tcp_options);
    if (options.includes('8')) pushNote('Timestamp option is present, which FoxIO notes is common in Unix-like stacks.', 2);
    if (!options.includes('8')) pushNote('Timestamp option is absent, which FoxIO notes is common in Microsoft Windows stacks.', 2);
    if (options.includes('4')) pushNote('SACK Permitted is present, so the endpoint can use selective acknowledgments during loss recovery.', 10);
    if (options.includes('3')) pushNote('Window Scale is offered, so this endpoint expects receive windows larger than 65535 bytes.', 10);
    if (options.length && options[options.length - 1] === '0') pushNote('The option list ends with EOL padding; FoxIO specifically calls this out as a pattern often seen on iOS stacks.', 2);
    pushNote('Passive TCP stack hints describe the observed TCP edge. NAT, proxy firewalls, and normalization layers can blur the originating host identity.', 18);
    if (artifactType === 'ja4ts' && mss && mss < 1460 && shodanOs) {
      pushNote(`Reduced MSS in the passive server response should be read alongside the Shodan host context (${shodanOs}), because path overhead and host identity are separate questions.`, 18, 'conclusion');
    }
  }

  if (artifactType === 'ja4l' || artifactType === 'ja4ls') {
    const ttl = parseInteger(parts.observed_ttl);
    const latencyUs = parseInteger(parts.latency_microseconds);
    if (latencyUs !== null) pushNote(`JA4L records the observed SYN-to-SYN-ACK timing span as ${formatNumber(latencyUs)} microseconds.`, 1);
    if (ttl !== null) {
      const hop = estimateHopCount(ttl);
      const initial = inferInitialTtl(ttl);
      if (hop !== null && initial !== null) pushNote(`Observed TTL ${ttl} most likely came from an initial TTL of ${initial}, which implies roughly ${hop} routed hops.`, 1);
    }
    pushNote('TTL and hop-distance style conclusions are path estimates. They are useful for rough distance reasoning, not exact geolocation or exact path reconstruction.', 18);
  }

  if (artifactType === 'ja4x') {
    if (parts.ja4x_a && parts.ja4x_a === parts.ja4x_b) pushNote('Issuer and subject structure hashes match. That often appears in self-signed or mirrored certificate layouts, though structure alone is not proof.', 1);
    if (parts.ja4x_c === '000000000000') pushNote('The extension hash is zeroed, which means no certificate extension OIDs were captured for this structure fingerprint.', 1);
    if (passiveCertificateAuthority && shodanCertificate.issuer && passiveCertificateAuthority === shodanCertificate.issuer) {
      pushNote('Passive packet certificate issuer matches the Shodan host certificate issuer, so the packet-side certificate context and the external host record reinforce each other.', 17, 'conclusion');
    }
    if (passiveCertificateSubject && shodanCertificate.subject && passiveCertificateSubject === shodanCertificate.subject) {
      pushNote('Passive packet certificate subject matches the Shodan host certificate subject, which increases confidence that the same certificate identity is being observed from both views.', 17, 'conclusion');
    }
    if (passiveDestinationDomain && Array.isArray(shodanCertificate.alt_names) && shodanCertificate.alt_names.map((item) => String(item).toLowerCase()).includes(passiveDestinationDomain)) {
      pushNote(`The Shodan certificate SAN list includes ${passiveDestinationDomain}, which supports the passive named-host context with certificate-level host identity evidence.`, 17, 'conclusion');
    }
  }

  if (artifactType === 'ja4ssh') {
    const sizes = parseJa4sshPair(parts.ja4ssh_a);
    const counts = parseJa4sshPair(parts.ja4ssh_b);
    const acks = parseJa4sshPair(parts.ja4ssh_c);
    if (sizes) pushNote(`The modal encrypted SSH payload sizes are client ${formatBytes(sizes.client)} and server ${formatBytes(sizes.server)} in this observation window.`, 1);
    if (counts) pushNote(`The window captured ${counts.client} client SSH payloads and ${counts.server} server SSH payloads.`, 1);
    if (acks) pushNote(`Bare ACK counts were client ${acks.client} and server ${acks.server}, which can help separate interactive sessions from bulk transfer patterns.`, 1);
    const envelopeNote = inferSshEnvelopeSemantics(sizes);
    if (envelopeNote) pushNote(envelopeNote, 16);
    if (counts && acks && counts.client <= 8 && counts.server <= 8 && acks.client + acks.server > counts.client + counts.server) {
      pushNote('This looks relatively chatty for a small amount of encrypted payload, which is more consistent with interactive shell behavior than sustained bulk transfer.', 16);
    }
    if (sizes && counts && sizes.server > sizes.client && counts.server >= counts.client * 2) {
      pushNote('Server payload volume dominates this window, which is more consistent with command output or download-like behavior than pure keystroke entry.', 16);
    }
    if (sizes && counts && sizes.client > sizes.server && counts.client >= counts.server * 2) {
      pushNote('Client payload volume dominates this window, which can happen with uploads, pasted commands, port forwarding, or other client-driven transfer.', 16);
    }
    if (counts && counts.client + counts.server <= 6) {
      pushNote('This is a very short SSH exchange window. It may only reflect setup, failed authentication, or an immediately closed session rather than steady post-login activity.', 16);
    }
    if (counts && counts.client >= 6 && counts.server === 0) {
      pushNote('Repeated client-side SSH payloads with little or no server payload in this window can fit guessing, failed auth, or a still-unanswered setup phase, but you need session-level aggregation before calling it brute force.', 15);
    }
    if (acks && acks.client + acks.server) {
      pushNote('ACK-heavy windows need sequence-context interpretation. TCP ACK cadence changes during recovery, so ACK counts alone are not a stand-alone verdict.', 20);
    }
    pushNote('Successful-login and brute-force heuristics are usually multi-event and environment-specific. Treat any single JA4SSH shape as suggestive, then confirm with session counts, timing, and surrounding flow context.', 15);
    pushNote('Per RFC 4253 and RFC 4254, SSH transport is encrypted and channel-multiplexed, but JA4SSH shape alone does not identify whether this was shell, exec, subsystem, or TCP forwarding traffic.', 12);
  }

  if (artifactType === 'jarm') {
    pushNote('JARM is an active TLS server fingerprint built from 10 specially crafted ClientHello probes.', 7);
    pushNote('The first 30 characters encode the TLS version and cipher choices the server made across those 10 probes.', 7);
    pushNote('The last 32 characters are a truncated SHA256 hash of the cumulative extension behavior, excluding X.509 certificate data.', 7);
    const first = String(parts.jarm_first_30 || '');
    const triplets = [];
    for (let index = 0; index < first.length; index += 3) {
      triplets.push(first.slice(index, index + 3));
    }
    if (triplets.includes('000')) {
      pushNote('A 000 triplet in the first half means the server refused to negotiate for at least one of the JARM probe styles.', 7);
    }
    if (isAllZeroJarm(artifact?.artifact_value)) {
      pushNote('An all-zero JARM usually means the target did not complete meaningful TLS negotiation on the tested host and port.', 7, 'conclusion');
    }
    if (first && parts.jarm_last_32) {
      pushNote('If another JARM matches only the first 30 characters, the servers likely share version and cipher behavior but differ in extensions.', 7);
      pushNote('If another JARM matches only the last 32 characters, the extension behavior aligns but the negotiated version and cipher choices differ.', 7);
    }
  }

  if (serverSideArtifact && shodanOs) {
    pushNote(`Shodan host data reports the destination OS as ${shodanOs}. Treat that as stronger host context than passive stack-guess notes alone.`, 17, 'conclusion');
  }
  if (serverSideArtifact && shodanTechnologies.length) {
    pushNote(`Shodan observed web technologies on the destination host: ${shodanTechnologies.join(', ')}.`, 17, 'conclusion');
  }
  if (serverSideArtifact && jarmResult?.jarm_fingerprint && !isAllZeroJarm(jarmResult.jarm_fingerprint)) {
    pushNote(`Active JARM data is available for the same destination, so passive server-side fingerprints can be compared against an active TLS response profile for the host.`, 7, 'conclusion');
  }
  if (serverSideArtifact && shodanCertificate.jarm && jarmResult?.jarm_fingerprint && !isAllZeroJarm(jarmResult.jarm_fingerprint)) {
    if (shodanCertificate.jarm === jarmResult.jarm_fingerprint) {
      pushNote('The active JARM result matches the JARM value exposed in Shodan host data, so both active probe views agree on the server TLS response profile.', 7, 'conclusion');
    } else {
      pushNote('The active JARM result differs from the JARM value exposed in Shodan host data. That can happen with load balancing, CDN edges, time-varying configuration, or vantage differences.', 7, 'conclusion');
    }
  }
  if (artifactType === 'ja4x' && shodanHostLookup?.certificate?.issuer) {
    pushNote(`Certificate structure can now be compared with Shodan certificate context for the same destination, which improves confidence over JA4X structure alone.`, 1, 'conclusion');
  }
  if (serverSideArtifact && passiveDestinationDomain) {
    const normalizedShodanNames = dedupePreserveOrder([...shodanDomains, ...shodanHostnames].map((item) => String(item || '').trim().toLowerCase())).filter(Boolean);
    if (normalizedShodanNames.includes(passiveDestinationDomain)) {
      pushNote(`Shodan host data also lists ${passiveDestinationDomain}, so the passive packet hostname and the external host record point at the same named destination.`, 17, 'conclusion');
    }
  }
  if (serverSideArtifact && shodanPrimaryIp && packet.dst_ip && shodanPrimaryIp === String(packet.dst_ip).trim()) {
    pushNote(`Shodan host details were resolved against the same public IP seen in the packet (${shodanPrimaryIp}), which makes the enrichment directly relevant to this server-side fingerprint set.`, 17, 'conclusion');
  }

  const scrubbed = scrubInferenceConflicts(notes, {
    artifactType,
    shodanOs,
    shodanTechnologies,
  });

  return dedupeInferenceItems(scrubbed);
}

function isServerSideArtifactType(artifactType) {
  return new Set(['ja4s', 'ja4ts', 'ja4x', 'ja4ls']).has(String(artifactType || '').toLowerCase());
}

function scrubInferenceConflicts(notes, context = {}) {
  const artifactType = String(context.artifactType || '').toLowerCase();
  const shodanOs = String(context.shodanOs || '').toLowerCase();
  if (!shodanOs) return notes;

  return notes.filter((note) => {
    const text = String(note?.text || '');
    if (artifactType === 'ja4ts' || artifactType === 'ja4ls') {
      if (shodanOs.includes('linux') || shodanOs.includes('ubuntu') || shodanOs.includes('debian') || shodanOs.includes('unix')) {
        if (text.includes('common in Microsoft Windows stacks.')) return false;
      }
      if (shodanOs.includes('windows')) {
        if (text.includes('common in Unix-like stacks.')) return false;
        if (text.includes('often seen on iOS stacks.')) return false;
      }
    }
    return true;
  });
}

function dedupeInferenceItems(items) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const text = String(item?.text || '');
    if (!text || seen.has(text)) continue;
    seen.add(text);
    output.push(item);
  }
  return output;
}

function rerenderPacketDetailPreservingPosition(packetId) {
  const detailRow = document.getElementById(`detail-row-${packetId}`);
  if (!detailRow) {
    renderDetailRow(packetId);
    return;
  }
  const topBefore = detailRow.getBoundingClientRect().top;
  renderDetailRow(packetId);
  const topAfter = detailRow.getBoundingClientRect().top;
  const delta = topAfter - topBefore;
  if (delta) window.scrollBy(0, delta);
}

function getSuggestedJarmPort(packetId, packet = {}) {
  const state = getPacketState(packetId);
  const explicitPort = Number.parseInt(String(state.jarmTargetPort || '').trim(), 10);
  if (Number.isInteger(explicitPort) && explicitPort > 0 && explicitPort <= 65535) return explicitPort;

  const packetPort = Number(packet?.dst_port || 0);
  const shodanPorts = Array.isArray(state.shodanResult?.host_lookup?.ports)
    ? state.shodanResult.host_lookup.ports.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0)
    : [];
  const tlsPorts = new Set([443, 8443, 9443, 10443, 4443]);
  if (tlsPorts.has(packetPort)) return packetPort;
  if (shodanPorts.includes(443)) return 443;
  if (packetPort > 0 && packetPort !== 80 && packetPort !== 8080) return packetPort;
  return 443;
}

function getShodanTarget(packet = {}, inspector = {}) {
  const destinationDomain = String(inspector.destination_domain || '').trim();
  const destinationIp = String(packet.dst_ip || '').trim();
  if (destinationDomain) return { enabled: true, reason: '' };
  if (isPublicIp(destinationIp)) return { enabled: true, reason: '' };
  return {
    enabled: false,
    reason: 'Shodan needs a public destination IP or a destination domain from this packet row.',
  };
}

function isPublicIp(value) {
  const text = String(value || '').trim();
  if (!text || text.includes(':')) return false;
  const parts = text.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  if (parts[0] === 10) return false;
  if (parts[0] === 127) return false;
  if (parts[0] === 0) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] >= 224) return false;
  return true;
}

function inferHttpMethodSemantics(code) {
  const normalized = String(code || '').toLowerCase();
  const mapping = {
    ge: 'GET is the standard retrieval method and is defined as safe and idempotent.',
    he: 'HEAD is a metadata-only form of GET, so the response semantics mirror GET without transferring the response content.',
    po: 'POST is for resource-specific processing and is not inherently idempotent, so repeated requests can have different effects.',
    pu: 'PUT is intended to replace the target representation and is defined as idempotent.',
    de: 'DELETE is a state-changing method and is defined as idempotent, even though the resource state is being removed.',
    co: 'CONNECT establishes a tunnel, so this often reflects proxy traversal or HTTPS-style tunneling rather than ordinary origin retrieval.',
    op: 'OPTIONS asks for communication options or capabilities and is commonly seen in discovery and CORS preflight patterns.',
    tr: 'TRACE requests a loop-back of the received message for diagnostics, and many production deployments disable it.',
    pa: 'PATCH is for partial modification rather than full replacement, so it usually points to API-style update workflows.',
  };
  return mapping[normalized] || '';
}

function inferHttpVersionSemantics(code, methodCode = '') {
  const normalized = String(code || '');
  if (normalized === '09') return 'HTTP/0.9 was the original minimal form and was limited to simple retrieval semantics.';
  if (normalized === '10') return 'HTTP/1.0 is an older text protocol version and does not assume persistent connections by default.';
  if (normalized === '11') return 'HTTP/1.1 adds Host-based routing and default persistent connections, so it is the classic modern text HTTP shape.';
  if (normalized === '20') return 'HTTP/2 keeps HTTP semantics but moves them onto a binary, multiplexed framing layer.';
  if (normalized === '30') return 'HTTP/3 keeps HTTP semantics but runs over QUIC rather than TCP.';
  if (String(methodCode || '').toLowerCase() === 'co') return 'CONNECT semantics are especially tied to tunneling behavior regardless of HTTP version.';
  return '';
}

function inferTlsVersionSemantics(code) {
  const normalized = String(code || '').toLowerCase();
  if (normalized === '13') return 'TLS 1.3 removed legacy key exchange modes, encrypts handshake messages after ServerHello, and can support 0-RTT when the application profile allows it.';
  if (normalized === '12') return 'TLS 1.2 is the long-lived mainstream legacy version before TLS 1.3, with broader historical cipher-suite variation than TLS 1.3.';
  if (normalized === '11' || normalized === '10') return 'TLS 1.0 and 1.1 are legacy protocol versions now kept mostly for compatibility with older stacks.';
  if (normalized === 's3') return 'SSL 3.0 is a Historic protocol and should be treated as legacy traffic rather than a modern secure baseline.';
  if (normalized === 's2') return 'SSL 2.0 is an obsolete pre-TLS protocol, so its presence strongly suggests legacy or emulated behavior.';
  if (normalized === 'd1' || normalized === 'd2' || normalized === 'd3') return 'DTLS preserves TLS-like security semantics over datagram transport, so version meaning should be read in that context rather than as stream TLS.';
  return '';
}

function inferAlpnSemantics(code, transportCode = '') {
  const normalized = String(code || '').toLowerCase();
  const transport = String(transportCode || '').toLowerCase();
  if (normalized === 'h2') return 'ALPN indicates HTTP/2 semantics, which means concurrent request multiplexing on one connection.';
  if (normalized === 'h1') return 'ALPN indicates HTTP/1.x semantics, so this is more likely a text-framed HTTPS stack than HTTP/2 or HTTP/3.';
  if (normalized === 'h3') return transport === 'q'
    ? 'ALPN indicates HTTP/3 semantics over QUIC, which lines up cleanly with the QUIC transport code.'
    : 'ALPN suggests HTTP/3 semantics, which normally ride over QUIC, so a non-QUIC transport code here is worth double-checking.';
  if (normalized === '00') return 'No ALPN token was advertised or negotiated.';
  return '';
}

function inferSshEnvelopeSemantics(sizes) {
  if (!sizes) return '';
  const client = sizes.client;
  if (client === 36) return 'A 36-byte modal client SSH payload is in the range passive analysts have associated with single-keystroke-sized interactive traffic under some ChaCha20-Poly1305 cases.';
  if (client === 40) return 'A 40-byte modal client SSH payload is in the range passive analysts have associated with single-keystroke-sized interactive traffic under some ETM MAC cases.';
  if (client === 52) return 'A 52-byte modal client SSH payload is in the range passive analysts have associated with single-keystroke-sized interactive traffic under some non-ETM MAC cases.';
  if (client >= 288 && client <= 320) return 'A modal client SSH payload in the 288 to 320 byte range can line up with PTY or terminal-capability setup seen just after successful interactive login on some clients.';
  return '';
}

function mapHttpMethodCode(code) {
  const mapping = {
    ge: 'GET',
    po: 'POST',
    pu: 'PUT',
    de: 'DELETE',
    he: 'HEAD',
    op: 'OPTIONS',
    co: 'CONNECT',
    tr: 'TRACE',
    pa: 'PATCH',
  };
  return mapping[String(code || '').toLowerCase()] || '';
}

function mapHttpVersionCode(code) {
  const mapping = {
    '09': 'HTTP/0.9',
    '10': 'HTTP/1.0',
    '11': 'HTTP/1.1',
    '20': 'HTTP/2',
    '30': 'HTTP/3',
  };
  return mapping[String(code || '')] || '';
}

function mapAcceptLanguageCode(code) {
  const normalized = String(code || '').toLowerCase();
  if (!normalized || normalized === '0000') return 'not advertised';
  return normalized.replace(/0+$/g, '') || normalized;
}

function mapJa4Protocol(code) {
  const mapping = {
    t: 'TLS over TCP',
    q: 'QUIC',
    d: 'DTLS',
  };
  return mapping[String(code || '').toLowerCase()] || '';
}

function mapTlsVersionCode(code) {
  const mapping = {
    '13': 'TLS 1.3',
    '12': 'TLS 1.2',
    '11': 'TLS 1.1',
    '10': 'TLS 1.0',
    s3: 'SSL 3.0',
    s2: 'SSL 2.0',
    d1: 'DTLS 1.0',
    d2: 'DTLS 1.2',
    d3: 'DTLS 1.3',
    '00': 'unknown version',
  };
  return mapping[String(code || '').toLowerCase()] || '';
}

function mapAlpnCode(code) {
  const normalized = String(code || '').toLowerCase();
  const mapping = {
    h2: 'HTTP/2',
    h1: 'HTTP/1.x',
    h3: 'HTTP/3',
    d1: 'DoQ or another d...1 token',
    '00': 'no ALPN advertised',
  };
  return mapping[normalized] || (normalized ? `ALPN edge code ${normalized}` : '');
}

function parseInteger(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number.parseInt(String(value), 10);
  return Number.isFinite(number) ? number : null;
}

function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatBytes(value) {
  const bytes = typeof value === 'number' ? value : parseInteger(value);
  if (bytes === null) return '';
  const formattedBytes = `${formatNumber(bytes)} bytes`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let unitIndex = -1;
  let scaled = bytes;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  if (unitIndex < 0) return formattedBytes;
  const decimals = scaled >= 100 ? 1 : scaled >= 10 ? 2 : 2;
  return `${formattedBytes} (${scaled.toFixed(decimals)} ${units[unitIndex]})`;
}

function parseTcpOptions(value) {
  return String(value || '')
    .split('-')
    .map((item) => item.trim())
    .filter(Boolean);
}

function describeTcpOptions(value) {
  const mapping = {
    '0': 'EOL',
    '1': 'NOP',
    '2': 'MSS',
    '3': 'Window Scale',
    '4': 'SACK Permitted',
    '8': 'Timestamps',
  };
  const described = parseTcpOptions(value).map((item) => mapping[item] || `Option ${item}`);
  return described.length ? described.join(', ') : 'no TCP options';
}

function describeMssValue(value) {
  const mss = parseInteger(value);
  if (mss === null) return '';
  if (mss === 1460) return 'common Ethernet MTU 1500 path';
  if (mss < 1460) return 'reduced path MTU or added tunnel overhead';
  return 'larger-than-usual MTU assumption';
}

function computeScaledWindow(windowSize, windowScale) {
  const base = typeof windowSize === 'number' ? windowSize : parseInteger(windowSize);
  const scale = typeof windowScale === 'number' ? windowScale : parseInteger(windowScale);
  if (base === null || scale === null) return null;
  return base * (2 ** scale);
}

function inferInitialTtl(observedTtl) {
  const ttl = typeof observedTtl === 'number' ? observedTtl : parseInteger(observedTtl);
  if (ttl === null) return null;
  if (ttl <= 64) return 64;
  if (ttl <= 128) return 128;
  return 255;
}

function estimateHopCount(observedTtl) {
  const ttl = typeof observedTtl === 'number' ? observedTtl : parseInteger(observedTtl);
  const initial = inferInitialTtl(ttl);
  if (ttl === null || initial === null) return null;
  return Math.max(initial - ttl, 0);
}

function describeObservedTtl(value) {
  const ttl = parseInteger(value);
  if (ttl === null) return '';
  const initial = inferInitialTtl(ttl);
  const hops = estimateHopCount(ttl);
  if (initial === null || hops === null) return 'observed IP TTL';
  return `observed TTL, likely from initial ${initial} with about ${hops} hops`;
}

function parseJa4sshPair(value) {
  const match = String(value || '').match(/^c(\d+)s(\d+)$/i);
  if (!match) return null;
  return {
    client: Number.parseInt(match[1], 10),
    server: Number.parseInt(match[2], 10),
  };
}

function dedupePreserveOrder(items) {
  const seen = new Set();
  const output = [];
  for (const item of items) {
    const key = String(item || '');
    if (!key || seen.has(key)) continue;
    seen.add(key);
    output.push(key);
  }
  return output;
}

async function uploadPcap() {
  const fileInput = document.getElementById('pcap-file');
  const file = fileInput?.files?.[0];
  if (!file) {
    logLine('Select a PCAP before clicking Read PCAP.');
    return;
  }

  setWindowStatus('Reading PCAP...');
  logLine(`Uploading ${file.name}`);

  const form = new FormData();
  form.append('pcap', file);

  try {
    const response = await fetch('/api/upload-pcap', { method: 'POST', body: form });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || 'Upload failed');

    packetDetailCache.clear();
    packetUiState.clear();
    closeDrawer();
    closeCitationDrawer();
    currentSample = payload.sample;
    setSummary(payload.sample);
    setStats(payload.sample, payload.packets || [], payload.counts || null);
    renderPackets(payload.packets || []);
    setWindowStatus(payload.deduplicated ? 'Loaded cached sample' : 'Parsed sample');
    logLine(`${payload.deduplicated ? 'Reused cached parse for' : 'Parsed'} ${payload.sample.filename} with ${payload.packets.length} packet rows.`);
  } catch (error) {
    setWindowStatus('Read failed');
    logLine(`Upload failed: ${error.message}`);
  }
}

function wireEvents() {
  document.querySelectorAll('[data-input-mode]').forEach((button) => {
    button.addEventListener('click', () => setInputMode(button.dataset.inputMode));
  });
  document.getElementById('pcap-file')?.addEventListener('change', (event) => {
    const file = event.target.files?.[0];
    document.getElementById('pcap-file-name').value = file ? file.name : 'No file selected';
  });
  document.getElementById('standalone-analyze-button')?.addEventListener('click', analyzeStandaloneHash);
  document.getElementById('standalone-hash-value')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      analyzeStandaloneHash();
    }
  });
  document.getElementById('read-pcap-button')?.addEventListener('click', uploadPcap);
  document.getElementById('export-button')?.addEventListener('click', openExportDrawer);
  document.getElementById('drawer-close')?.addEventListener('click', closeDrawer);
  document.getElementById('drawer-overlay')?.addEventListener('click', closeDrawer);
  document.getElementById('citation-close')?.addEventListener('click', closeCitationDrawer);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeDrawer();
      closeCitationDrawer();
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  wireEvents();
  setInputMode('pcap');
  renderStandaloneAnalysisToDom(null);
});
