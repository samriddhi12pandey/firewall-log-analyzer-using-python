/* ── Helpers ── */
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => (
  {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]
));

async function api(url, opts) {
  const r = await fetch(url, opts);
  let d = null;
  try { d = await r.json(); } catch (_) {}
  if (!r.ok || (d && d.error)) throw new Error((d && d.error) || `HTTP ${r.status}`);
  return d;
}

const jsonOpts = (method, body) => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

function isValidIP(ip) {
  const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  return v4.test(ip) || (ip.includes(':') && v6.test(ip));
}

function renderAll(data) {
  updateStats(data);
  buildCharts(data);
  renderThreats(data.threats || []);
  renderTable(data.recent || [], data.total, 0);
}

/* ── API ── */
async function loadSample() {
  showLoader(true);
  try {
    const d = await api('/api/sample');
    renderAll(d);
    toast(`✅ ${fmt(d.total)} events loaded`, 'success');
  } catch (e) {
    toast('❌ Error: ' + e.message, 'error');
  } finally { showLoader(false); }
}

async function handleUpload() {
  const file = el('file-input').files[0];
  if (!file) { toast('No file — loading sample'); loadSample(); return; }
  const fd = new FormData();
  fd.append('file', file);
  showLoader(true);
  try {
    const d = await api('/api/upload', { method: 'POST', body: fd });
    renderAll(d);
    toast(`✅ ${fmt(d.total)} entries from ${file.name}`, 'success');
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  } finally { showLoader(false); }
}

async function fetchFiltered(page = 0) {
  const params = new URLSearchParams({
    search: el('f-search').value, src_ip: el('f-ip').value, action: el('f-action').value,
    protocol: el('f-proto').value, port: el('f-port').value,
    blacklisted: el('f-blacklisted').checked ? '1' : '', page, per_page: PER_PAGE
  });
  return api('/api/filter?' + params);
}

async function applyFilter() {
  showLoader(true);
  try {
    const d = await fetchFiltered(0);
    renderTable(d.logs || [], d.total, 0);
    toast(`${fmt(d.total)} results`);
  } catch (e) {
    toast('❌ Filter error: ' + e.message, 'error');
  } finally { showLoader(false); }
}

function clearFilter() {
  ['f-search', 'f-ip', 'f-port', 'f-action', 'f-proto'].forEach(id => el(id).value = '');
  el('f-blacklisted').checked = false;
  applyFilter();
}

async function changePage(dir) {
  const max = Math.max(0, Math.ceil(filteredTotal / PER_PAGE) - 1);
  const pg = Math.max(0, Math.min(max, currentPage + dir));
  if (pg === currentPage) return;
  showLoader(true);
  try {
    const d = await fetchFiltered(pg);
    renderTable(d.logs || [], d.total, pg);
  } catch (e) {
    toast('❌ Page error: ' + e.message, 'error');
  } finally { showLoader(false); }
}

/* ── Blacklist ── */
async function addBlacklist() {
  const ip = el('bl-ip-input').value.trim();
  if (!ip) { toast('Enter an IP address', 'error'); return; }
  if (!isValidIP(ip)) { toast('Invalid IP address', 'error'); return; }
  try {
    const d = await api('/api/blacklist', jsonOpts('POST', { ip }));
    toast(`🚫 ${ip} blacklisted! Total: ${d.count}`, 'success');
    el('bl-ip-input').value = '';
    loadBlacklistUI();
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  }
}

async function quickBlacklist(ip) {
  try {
    await api('/api/blacklist', jsonOpts('POST', { ip }));
    toast(`🚫 ${ip} blacklisted!`, 'success');
    if (el('blacklist-table')) loadBlacklistUI();
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  }
}

async function removeBlacklist(ip) {
  try {
    await api('/api/blacklist', jsonOpts('DELETE', { ip }));
    toast(`✅ ${ip} removed`, 'success');
    loadBlacklistUI();
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  }
}

async function loadBlacklistUI() {
  const box = el('blacklist-table');
  try {
    const d = await api('/api/blacklist');
    const bl = d.blacklist || [];
    if (!bl.length) {
      box.innerHTML = `<div class="empty-state"><div class="e-icon">🚫</div><p>No IPs blacklisted yet</p></div>`;
      return;
    }
    box.innerHTML = `<table class="bl-table">
      <thead><tr><th>#</th><th>IP Address</th><th>Action</th></tr></thead>
      <tbody>${bl.map((ip, i) => `<tr>
        <td style="color:var(--dim)">${i + 1}</td>
        <td style="color:var(--red)">${esc(ip)}</td>
        <td><button class="bl-btn" data-ip="${esc(ip)}">✕ Remove</button></td></tr>`).join('')}
      </tbody></table>`;
    box.querySelectorAll('.bl-btn').forEach(b =>
      b.addEventListener('click', () => removeBlacklist(b.dataset.ip)));
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  }
}

/* ── Geo Map ── */
let geoLayer = null;   // (geoMap pehle se declared hona chahiye: let geoMap = null;)

function initMap() {
  geoMap = L.map('geo-map', { center: [20, 0], zoom: 2 });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '©OpenStreetMap ©CartoDB', maxZoom: 18
  }).addTo(geoMap);
  geoLayer = L.layerGroup().addTo(geoMap);
}

async function loadGeoMap() {
  if (!geoMap) initMap();
  setTimeout(() => geoMap.invalidateSize(), 100);   // hidden tab fix
  showLoader(true);
  try {
    const d = await api('/api/geo');
    const points = d.points || [];
    geoLayer.clearLayers();
    points.forEach(p => {
      const lat = Number(p.lat), lon = Number(p.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon) || (lat === 0 && lon === 0)) return;
      const radius = Math.max(6, Math.min(24, (p.count || 0) / 3));
      L.circleMarker([lat, lon], {
        radius, fillColor: '#f05050', color: '#ff6666',
        weight: 1, opacity: 0.9, fillOpacity: 0.6
      }).addTo(geoLayer).bindPopup(
        `<div class="geo-popup"><b>${esc(p.ip)}</b><br>${esc(p.city)}, ${esc(p.country)}<br>Blocked: <b>${esc(p.count)}x</b></div>`
      );
    });
    el('geo-list').innerHTML = `<table class="bl-table">
      <thead><tr><th>IP</th><th>Country</th><th>City</th><th>Blocked Count</th></tr></thead>
      <tbody>${points.map(p => `<tr>
        <td style="color:var(--red)">${esc(p.ip)}</td><td>${esc(p.country)}</td>
        <td>${esc(p.city)}</td><td style="color:var(--amber)">${esc(p.count)}</td></tr>`).join('')}
      </tbody></table>`;
    toast(`🌍 ${points.length} IPs mapped`, 'success');
  } catch (e) {
    toast('❌ Map error: ' + e.message, 'error');
  } finally { showLoader(false); }
}

/* ── Email config ── */
async function saveEmailConfig() {
  const config = {
    smtp: el('e-smtp').value.trim(),
    port: parseInt(el('e-port').value, 10) || 587,
    user: el('e-user').value.trim(),
    password: el('e-pass').value,
    to: el('e-to').value.trim(),
    enabled: el('e-enabled').checked
  };
  try {
    const d = await api('/api/email_config', jsonOpts('POST', config));
    toast('📧 ' + d.message, 'success');
  } catch (e) {
    toast('❌ ' + e.message, 'error');
  }
}

async function loadEmailConfig() {
  try {
    const d = await api('/api/email_config');
    el('e-smtp').value = d.smtp || '';
    el('e-port').value = d.port || 587;
    el('e-user').value = d.user || '';
    el('e-to').value = d.to || '';
    el('e-enabled').checked = !!d.enabled;
  } catch (e) { /* config abhi set nahi hai, ignore */ }
}

/* ── Export ── */
function downloadURL(url) {
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  a.remove();
}
function exportCSV() { downloadURL('/api/export/csv'); toast('⬇ CSV downloading...'); }
function exportPDF() { downloadURL('/api/export/pdf'); toast('⬇ PDF generating...'); }

/* ── Init (DOM ready ke baad) ── */
window.addEventListener('DOMContentLoaded', () => {
  const dz = el('drop-zone');
  const input = el('file-input');

  if (dz) {
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('hover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('hover'));
    dz.addEventListener('drop', e => {
      e.preventDefault();
      dz.classList.remove('hover');
      const f = e.dataTransfer.files[0];
      if (!f) return;
      input.files = e.dataTransfer.files;       // ← asli fix: file input mein set karo
      el('file-name').textContent = f.name;
      toast('File ready — click Analyze');
    });
  }

  input.addEventListener('change', e => {
    if (e.target.files[0]) el('file-name').textContent = e.target.files[0].name;
  });

  loadEmailConfig();
  setTimeout(loadSample, 400);
});
