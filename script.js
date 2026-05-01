let chart;
let history = [];

/* =======================
   SECTION SWITCH
======================= */
function showSection(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
  document.getElementById(id).classList.add("active");
}

/* =======================
   DEMO BUTTON
======================= */
function useDemo() {
  const data = {
    total_logs: 50,
    blocked: Math.floor(Math.random() * 20),
    top_ips: [
      { ip: "192.168.1.1", count: 10 },
      { ip: "10.0.0.2", count: 7 },
      { ip: "172.16.0.5", count: 5 }
    ]
  };

  updateUI(data);
}

/* =======================
   BACKEND ANALYZE (IMPORTANT)
======================= */
async function uploadFile() {
  const fileInput = document.getElementById("fileInput");

  if (!fileInput.files.length) {
    alert("Please select a log file");
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  try {
    const response = await fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      body: formData
    });

    if (!response.ok) {
      throw new Error("Server error");
    }

    const data = await response.json();
    updateUI(data);

  } catch (error) {
    alert("❌ Cannot connect to backend.\nMake sure Flask is running.");
    console.error(error);
  }
}

/* =======================
   UPDATE UI
======================= */
function updateUI(data) {
  document.getElementById("totalLogs").innerText = data.total_logs;
  document.getElementById("blocked").innerText = data.blocked;

  let threatLevel = "LOW";
  if (data.blocked > 10) threatLevel = "HIGH";
  else if (data.blocked > 5) threatLevel = "MEDIUM";

  document.getElementById("threat").innerText = threatLevel;
  document.getElementById("circleValue").innerText = threatLevel;

  document.getElementById("aiInsights").innerText =
    threatLevel === "HIGH" ? "🚨 High Threat" :
    threatLevel === "MEDIUM" ? "⚠ Suspicious" :
    "✔ Safe";

  const ipList = document.getElementById("ipList");
  ipList.innerHTML = "";

  data.top_ips.forEach(ip => {
    let li = document.createElement("li");
    li.textContent = `${ip.ip} (${ip.count})`;
    ipList.appendChild(li);
  });

  renderChart(data);
  saveHistory(data);
  generateMap();
}

/* =======================
   CHART
======================= */
function renderChart(data) {
  if (chart) chart.destroy();

  const ctx = document.getElementById("chartCanvas");

  chart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: data.top_ips.map(i => i.ip),
      datasets: [{
        label: "Traffic",
        data: data.top_ips.map(i => i.count),
        backgroundColor: "#007bff"
      }]
    }
  });
}

/* =======================
   HISTORY
======================= */
function saveHistory(data) {
  history.push(data);

  const historyList = document.getElementById("historyList");
  historyList.innerHTML = "";

  history.forEach((h, i) => {
    let li = document.createElement("li");
    li.textContent = `Run ${i + 1}: ${h.total_logs} logs`;
    historyList.appendChild(li);
  });
}

/* =======================
   MAP
======================= */
function generateMap() {
  const map = document.getElementById("map");
  if (!map) return;

  map.innerHTML = "";

  for (let i = 0; i < 10; i++) {
    let dot = document.createElement("div");
    dot.className = "dot";
    dot.style.left = Math.random() * 90 + "%";
    dot.style.top = Math.random() * 90 + "%";
    map.appendChild(dot);
  }
}

/* =======================
   LIVE FEED
======================= */
setInterval(() => {
  const liveFeed = document.getElementById("liveFeed");
  if (!liveFeed) return;

  let div = document.createElement("div");
  div.textContent = "Traffic detected...";
  liveFeed.prepend(div);
}, 2000);

/* =======================
   TERMINAL
======================= */
setInterval(() => {
  const terminal = document.getElementById("terminal");
  if (!terminal) return;

  terminal.innerHTML = "> scanning...<br>" + terminal.innerHTML;
}, 1500);

/* =======================
   DOWNLOAD
======================= */
function downloadReport() {
  let blob = new Blob([JSON.stringify(history, null, 2)], { type: "text/plain" });

  let a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "report.txt";
  a.click();
}

/* =======================
   UI CONTROLS
======================= */
function toggleTheme() {
  document.body.classList.toggle("light");
}

function toggleSound() {
  alert("Sound toggled (demo)");
}