/* Firewall Log Analyzer v2.0 — Frontend */
const C={amber:'#e8a030',amber2:'#f5c842',green:'#4ade80',red:'#f05050',blue:'#60a5fa',dim:'#5a5a42',text:'#d4d0b8',grid:'rgba(42,42,30,0.5)'};
let charts={},currentPage=0,filteredTotal=0,allThreats=[],geoMap=null;
const PER_PAGE=50;
const el=id=>document.getElementById(id);
const fmt=n=>Number(n).toLocaleString();

/* ── Toast ── */
function toast(msg,type=''){
  const t=el('toast');t.textContent=msg;
  t.style.borderColor=type==='error'?'#f05050':type==='success'?'#4ade80':'#e8a030';
  t.style.color=type==='error'?'#f05050':type==='success'?'#4ade80':'#e8a030';
  t.classList.add('show');setTimeout(()=>t.classList.remove('show'),3000);
}
function showLoader(v){el('overlay').classList.toggle('show',v);}

/* ── Theme toggle ── */
function toggleTheme(){
  const html=document.documentElement;
  const isDark=html.getAttribute('data-theme')==='dark';
  html.setAttribute('data-theme',isDark?'light':'dark');
  toast(isDark?'☀️ Light mode on':'🌙 Dark mode on');
  rebuildCharts();
}

/* ── Tabs ── */
function showTab(name){
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el('tab-'+name).classList.add('active');
  event.target.classList.add('active');
  if(name==='map') setTimeout(()=>{ if(!geoMap) initMap(); loadGeoMap(); },100);
  if(name==='blacklist') loadBlacklistUI();
  if(name==='alerts') renderThreats(allThreats);
}

/* ── Animated counter ── */
function animateVal(id,target){
  const el2=el(id); let start=parseInt(el2.textContent.replace(/,/g,''))||0;
  const diff=target-start; const steps=20;
  let i=0;
  const t=setInterval(()=>{
    i++;el2.textContent=fmt(Math.round(start+(diff*i/steps)));
    if(i>=steps){el2.textContent=fmt(target);clearInterval(t);el2.classList.add('counting');setTimeout(()=>el2.classList.remove('counting'),400);}
  },30);
}

/* ── Chart helpers ── */
function isDark(){return document.documentElement.getAttribute('data-theme')!=='light';}
function getC(){return isDark()?{text:'#d4d0b8',dim:'#5a5a42',grid:'rgba(42,42,30,0.5)'}:{text:'#1a1a0e',dim:'#888870',grid:'rgba(200,200,180,0.5)'};}
function baseOpts(type){
  const c=getC();
  const o={responsive:true,plugins:{legend:{labels:{color:c.text,font:{family:'IBM Plex Mono',size:10},boxWidth:12}}}};
  if(type==='line'||type==='bar'){o.scales={x:{ticks:{color:c.dim,font:{size:9}},grid:{color:c.grid}},y:{ticks:{color:c.dim,font:{size:9}},grid:{color:c.grid}}};}
  return o;
}
function killChart(id){if(charts[id]){charts[id].destroy();delete charts[id];}}
function rebuildCharts(){if(Object.keys(charts).length)buildCharts(window._lastStats||{});}

function buildCharts(s){
  window._lastStats=s;
  const hours=Object.keys(s.hourly||{}).sort();
  killChart('tl');
  charts['tl']=new Chart(el('chart-timeline'),{type:'line',
    data:{labels:hours,datasets:[{label:'Events/hr',data:hours.map(h=>s.hourly[h]),
      borderColor:C.amber,backgroundColor:'rgba(232,160,48,0.08)',fill:true,tension:0.4,pointRadius:3,pointBackgroundColor:C.amber,borderWidth:1.5}]},
    options:{...baseOpts('line'),plugins:{legend:{display:false}}}});
  killChart('act');
  charts['act']=new Chart(el('chart-actions'),{type:'doughnut',
    data:{labels:['ALLOW','BLOCK'],datasets:[{data:[s.allowed,s.blocked],backgroundColor:['rgba(74,222,128,0.7)','rgba(240,80,80,0.7)'],borderColor:['#4ade80','#f05050'],borderWidth:1}]},
    options:{...baseOpts('doughnut'),cutout:'65%'}});
  killChart('ips');
  const ipKeys=Object.keys(s.top_src||{}).slice(0,8);
  charts['ips']=new Chart(el('chart-ips'),{type:'bar',
    data:{labels:ipKeys,datasets:[{label:'Connections',data:ipKeys.map(k=>s.top_src[k]),backgroundColor:'rgba(232,160,48,0.4)',borderColor:C.amber,borderWidth:1,borderRadius:1}]},
    options:{...baseOpts('bar'),indexAxis:'y',plugins:{legend:{display:false}},
      scales:{x:{ticks:{color:getC().dim,font:{size:9}},grid:{color:getC().grid}},y:{ticks:{color:C.amber,font:{size:9,family:'IBM Plex Mono'}},grid:{color:getC().grid}}}}});
  killChart('pr');
  charts['pr']=new Chart(el('chart-proto'),{type:'pie',
    data:{labels:Object.keys(s.protocols||{}),datasets:[{data:Object.values(s.protocols||{}),backgroundColor:['rgba(96,165,250,0.7)','rgba(232,160,48,0.7)','rgba(240,80,80,0.7)','rgba(74,222,128,0.7)'],borderColor:'#0a0a08',borderWidth:2}]},
    options:baseOpts('pie')});
  killChart('po');
  const portKeys=Object.keys(s.top_ports||{}).slice(0,8);
  charts['po']=new Chart(el('chart-ports'),{type:'bar',
    data:{labels:portKeys,datasets:[{label:'Hits',data:portKeys.map(k=>s.top_ports[k]),backgroundColor:'rgba(96,165,250,0.4)',borderColor:C.blue,borderWidth:1,borderRadius:1}]},
    options:{...baseOpts('bar'),plugins:{legend:{display:false}}}});
}

/* ── Render ── */
function updateStats(d){
  animateVal('h-total',d.total);animateVal('h-blocked',d.blocked);
  animateVal('h-allowed',d.allowed);animateVal('h-threats',d.threat_count);
  animateVal('s-total',d.total);animateVal('s-blocked',d.blocked);
  animateVal('s-allowed',d.allowed);animateVal('s-threats',d.threat_count);
  animateVal('s-blacklist',d.blacklist_count||0);
  el('s-brate').textContent=`${d.block_rate}% blocked`;
}

function renderThreats(threats){
  allThreats=threats;
  el('threat-count-label').textContent=threats.length?`${threats.length} incidents`:'Clear';
  // Sidebar
  el('sidebar-threats').innerHTML=threats.length
    ?threats.slice(0,10).map(t=>`<div class="threat-mini"><div class="sev sev-${t.severity}"></div><div><div class="t-type">${t.type}</div><div class="t-ip">${t.src_ip}</div></div></div>`).join('')
    :`<div class="no-data-sm">✅ None detected</div>`;
  // Alerts tab
  if(!el('alerts-list'))return;
  if(!threats.length){el('alerts-list').innerHTML=`<div class="empty-state"><div class="e-icon">✅</div><p>No threats detected</p></div>`;return;}
  el('alerts-list').innerHTML=threats.map(t=>`
    <div class="alert-row ${t.severity}">
      <span class="a-sev">${t.severity}</span>
      <span class="a-type">${t.type}</span>
      <span class="a-ip">${t.src_ip}</span>
      <span class="a-detail">${t.detail}</span>
      <span class="a-bl"><button class="bl-btn" onclick="quickBlacklist('${t.src_ip}')">🚫 BLOCK</button></span>
    </div>`).join('');
}

function renderTable(logs,total,page){
  filteredTotal=total;currentPage=page;
  const start=page*PER_PAGE;
  el('table-info').textContent=`${start+1}–${Math.min(start+PER_PAGE,total)} of ${fmt(total)}`;
  el('page-info').textContent=`Page ${page+1} of ${Math.ceil(total/PER_PAGE)||1}`;
  el('btn-prev').disabled=page===0;el('btn-next').disabled=start+PER_PAGE>=total;
  if(!logs.length){el('log-tbody').innerHTML=`<tr><td colspan="9" class="td-empty">No entries</td></tr>`;return;}
  el('log-tbody').innerHTML=logs.map(l=>`
    <tr class="${l.blacklisted?'is-blacklisted':''}">
      <td class="c-ts">${l.timestamp}</td><td class="c-ip">${l.src_ip}</td><td class="c-ip2">${l.dst_ip}</td>
      <td class="c-port">${l.src_port}</td><td class="c-port">${l.dst_port}</td><td class="c-proto">${l.protocol}</td>
      <td><span class="badge badge-${l.action}">${l.action}</span></td>
      <td class="c-port">${l.bytes}</td>
      <td>${l.blacklisted?'<span class="badge-bl">🚫</span>':''}</td>
    </tr>`).join('');
}

function renderAll(data){
  updateStats(data);buildCharts(data);renderThreats(data.threats||[]);
  renderTable(data.recent||[],data.total,0);
}

/* ── API ── */
async function loadSample(){
  showLoader(true);
  try{const r=await fetch('/api/sample');const d=await r.json();renderAll(d);toast(`✅ ${fmt(d.total)} events loaded`,'success');}
  catch(e){toast('❌ Error: '+e.message,'error');}finally{showLoader(false);}
}

async function handleUpload(){
  const file=el('file-input').files[0];
  if(!file){toast('No file — loading sample');loadSample();return;}
  const fd=new FormData();fd.append('file',file);
  showLoader(true);
  try{const r=await fetch('/api/upload',{method:'POST',body:fd});const d=await r.json();
    if(d.error){toast('❌ '+d.error,'error');return;}
    renderAll(d);toast(`✅ ${fmt(d.total)} entries from ${file.name}`,'success');}
  catch(e){toast('❌ '+e.message,'error');}finally{showLoader(false);}
}

async function fetchFiltered(page=0){
  const params=new URLSearchParams({
    search:el('f-search').value,src_ip:el('f-ip').value,action:el('f-action').value,
    protocol:el('f-proto').value,port:el('f-port').value,
    blacklisted:el('f-blacklisted').checked?'1':'',page,per_page:PER_PAGE});
  const r=await fetch('/api/filter?'+params);return r.json();
}
async function applyFilter(){
  showLoader(true);
  try{const d=await fetchFiltered(0);renderTable(d.logs,d.total,0);toast(`${fmt(d.total)} results`);}
  catch(e){toast('❌ Filter error','error');}finally{showLoader(false);}
}
function clearFilter(){
  ['f-search','f-ip','f-port'].forEach(id=>el(id).value='');
  ['f-action','f-proto'].forEach(id=>el(id).value='');
  el('f-blacklisted').checked=false;applyFilter();
}
async function changePage(dir){
  const max=Math.ceil(filteredTotal/PER_PAGE)-1;
  const pg=Math.max(0,Math.min(max,currentPage+dir));
  if(pg===currentPage)return;
  showLoader(true);
  try{const d=await fetchFiltered(pg);renderTable(d.logs,d.total,pg);}
  catch(e){toast('❌ Page error','error');}finally{showLoader(false);}
}

/* ── Blacklist ── */
async function addBlacklist(){
  const ip=el('bl-ip-input').value.trim();
  if(!ip){toast('Enter an IP address','error');return;}
  const r=await fetch('/api/blacklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  const d=await r.json();
  toast(`🚫 ${ip} blacklisted! Total: ${d.count}`,'success');
  el('bl-ip-input').value='';loadBlacklistUI();
}
async function quickBlacklist(ip){
  const r=await fetch('/api/blacklist',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  const d=await r.json();toast(`🚫 ${ip} blacklisted!`,'success');
}
async function removeBlacklist(ip){
  await fetch('/api/blacklist',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
  toast(`✅ ${ip} removed`,'success');loadBlacklistUI();
}
async function loadBlacklistUI(){
  const r=await fetch('/api/blacklist');const d=await r.json();
  const bl=d.blacklist;
  if(!bl.length){el('blacklist-table').innerHTML=`<div class="empty-state"><div class="e-icon">🚫</div><p>No IPs blacklisted yet</p></div>`;return;}
  el('blacklist-table').innerHTML=`<table class="bl-table">
    <thead><tr><th>#</th><th>IP Address</th><th>Action</th></tr></thead>
    <tbody>${bl.map((ip,i)=>`<tr><td style="color:var(--dim)">${i+1}</td><td style="color:var(--red)">${ip}</td>
      <td><button class="bl-btn" onclick="removeBlacklist('${ip}')">✕ Remove</button></td></tr>`).join('')}
    </tbody></table>`;
}

/* ── Geo Map ── */
function initMap(){
  geoMap=L.map('geo-map',{center:[20,0],zoom:2});
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
    attribution:'©OpenStreetMap ©CartoDB',maxZoom:18}).addTo(geoMap);
}
async function loadGeoMap(){
  if(!geoMap)initMap();
  showLoader(true);
  try{
    const r=await fetch('/api/geo');const d=await r.json();
    // Clear old markers
    geoMap.eachLayer(l=>{if(l instanceof L.CircleMarker||l instanceof L.Marker)geoMap.removeLayer(l);});
    d.points.forEach(p=>{
      if(!p.lat&&!p.lon)return;
      const radius=Math.max(6,Math.min(24,p.count/3));
      const m=L.circleMarker([p.lat,p.lon],{radius,fillColor:'#f05050',color:'#ff6666',weight:1,opacity:0.9,fillOpacity:0.6}).addTo(geoMap);
      m.bindPopup(`<div class="geo-popup"><b>${p.ip}</b><br>${p.city}, ${p.country}<br>Blocked: <b>${p.count}x</b></div>`);
    });
    // Geo list
    el('geo-list').innerHTML=`<table class="bl-table"><thead><tr><th>IP</th><th>Country</th><th>City</th><th>Blocked Count</th></tr></thead>
      <tbody>${d.points.map(p=>`<tr><td style="color:var(--red)">${p.ip}</td><td>${p.country}</td><td>${p.city}</td><td style="color:var(--amber)">${p.count}</td></tr>`).join('')}</tbody></table>`;
    toast(`🌍 ${d.points.length} IPs mapped`,'success');
  }catch(e){toast('❌ Map error: '+e.message,'error');}finally{showLoader(false);}
}

/* ── Email config ── */
async function saveEmailConfig(){
  const config={smtp:el('e-smtp').value,port:parseInt(el('e-port').value),
    user:el('e-user').value,password:el('e-pass').value,to:el('e-to').value,enabled:el('e-enabled').checked};
  const r=await fetch('/api/email_config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)});
  const d=await r.json();toast('📧 '+d.message,'success');
}
async function loadEmailConfig(){
  try{const r=await fetch('/api/email_config');const d=await r.json();
    el('e-smtp').value=d.smtp||'';el('e-port').value=d.port||587;
    el('e-user').value=d.user||'';el('e-to').value=d.to||'';el('e-enabled').checked=d.enabled||false;
  }catch(e){}
}

/* ── Export ── */
function exportCSV(){window.location.href='/api/export/csv';toast('⬇ CSV downloading...');}
function exportPDF(){window.location.href='/api/export/pdf';toast('⬇ PDF generating...');}

/* ── Drag drop ── */
const dz=el('drop-zone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('hover');});
dz.addEventListener('dragleave',()=>dz.classList.remove('hover'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('hover');toast('File ready — click Analyze');});
el('file-input').addEventListener('change',e=>{if(e.target.files[0])el('file-name').textContent=e.target.files[0].name;});

/* ── Init ── */
window.addEventListener('load',()=>{
  loadEmailConfig();
  setTimeout(loadSample,400);
});
