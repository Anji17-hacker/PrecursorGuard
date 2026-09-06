const state = {
  mode: "hybrid",
  dataset: "baseline",
  selectedSession: null,
};

let riskChart = null;
let compareChart = null;

const VIEW_TITLES = {
  overview: ["Overview", "Hybrid rule + behavioral + ML detection"],
  alerts: ["Alerts", "Every scored session, ranked by risk"],
  mitre: ["MITRE ATT&CK Map", "Techniques matched by alerted sessions"],
  compare: ["Detector Comparison", "Why the hybrid approach exists"],
};

function setSubtitle() {
  const [title, sub] = VIEW_TITLES[currentView()];
  document.getElementById("view-title").textContent = title;
  const modeLabel = { hybrid: "Hybrid", rule_only: "Rule-only", ml_only: "ML-only" }[state.mode];
  const dsLabel = state.dataset === "baseline" ? "baseline evaluation set" : "unseen challenge set";
  document.getElementById("view-subtitle").textContent = `${sub} — ${modeLabel}, ${dsLabel}`;
}

function currentView() {
  return document.querySelector(".nav-item.active").dataset.view;
}

// ---------------- Nav ----------------

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    document.getElementById(`view-${btn.dataset.view}`).classList.add("active");
    setSubtitle();
    loadView(btn.dataset.view);
  });
});

document.querySelectorAll("#mode-group .pill").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#mode-group .pill").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.mode = btn.dataset.mode;
    setSubtitle();
    loadView(currentView());
  });
});

document.querySelectorAll("#dataset-group .pill").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#dataset-group .pill").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.dataset = btn.dataset.dataset;
    setSubtitle();
    loadView(currentView());
  });
});

document.getElementById("only-alerts-toggle").addEventListener("change", loadAlertsTable);

// ---------------- Loaders ----------------

function loadView(view) {
  if (view === "overview") loadOverview();
  if (view === "alerts") loadAlertsTable();
  if (view === "mitre") loadMitre();
  if (view === "compare") loadCompare();
}

async function loadOverview() {
  const res = await fetch(`/api/summary?mode=${state.mode}&dataset=${state.dataset}`);
  const d = await res.json();
  if (d.error) return;

  document.getElementById("kpi-total").textContent = d.total_sessions;
  document.getElementById("kpi-alerts").textContent = d.alerts_raised;
  document.getElementById("kpi-tp").textContent = d.true_positive;
  document.getElementById("kpi-precision").textContent = d.precision != null ? (d.precision * 100).toFixed(1) + "%" : "—";
  document.getElementById("kpi-fp").textContent = d.false_positive;
  document.getElementById("kpi-recall").textContent = d.recall != null ? (d.recall * 100).toFixed(1) + "%" : "—";
  document.getElementById("kpi-fn").textContent = d.false_negative;

  // Scenario bars
  const list = document.getElementById("scenario-list");
  list.innerHTML = "";
  const maxCount = Math.max(...d.by_scenario.map((s) => s.count), 1);
  d.by_scenario.forEach((s) => {
    const row = document.createElement("div");
    row.className = "scenario-row";
    row.innerHTML = `
      <div class="scenario-name">${s.scenario.replace(/_/g, " ")}</div>
      <div class="scenario-bar-wrap"><div class="scenario-bar" style="width:${(s.alerted / maxCount) * 100}%"></div></div>
      <div class="scenario-count">${s.alerted}/${s.count}</div>
    `;
    list.appendChild(row);
  });

  // Risk histogram
  const ctx = document.getElementById("chart-risk-hist");
  if (riskChart) riskChart.destroy();
  riskChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["0–0.2", "0.2–0.4", "0.4–0.6", "0.6–0.8", "0.8–1.0"],
      datasets: [{
        data: d.risk_histogram,
        backgroundColor: ["#7C8BC4", "#7C8BC4", "#F2A93C", "#F2A93C", "#FA5A6E"],
        borderRadius: 4,
        barThickness: 34,
      }],
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#8D97B8", font: { family: "IBM Plex Mono", size: 10.5 } } },
        y: { grid: { color: "#1B2740" }, ticks: { color: "#8D97B8" }, beginAtZero: true },
      },
    },
  });

  // Attack chain counts (from scenario breakdown, using alert row fields via /api/alerts)
  loadChainCounts();
}

async function loadChainCounts() {
  const res = await fetch(`/api/alerts?mode=${state.mode}&dataset=${state.dataset}&only_alerts=false`);
  const rows = await res.json();
  const cnt = (key) => rows.filter((r) => r[key] === true || (key === "precursor_command_count" && r[key] > 0)).length;
  document.getElementById("cnt-driver").textContent = cnt("rule_match");
  document.getElementById("cnt-priv").textContent = cnt("privilege_escalation_flag");
  document.getElementById("cnt-kill").textContent = cnt("security_process_killed");
  document.getElementById("cnt-precursor").textContent = cnt("precursor_command_count");
  document.getElementById("cnt-alert").textContent = rows.filter((r) => r.alert).length;
}

async function loadAlertsTable() {
  const onlyAlerts = document.getElementById("only-alerts-toggle").checked;
  const res = await fetch(`/api/alerts?mode=${state.mode}&dataset=${state.dataset}&only_alerts=${onlyAlerts}`);
  const rows = await res.json();
  const tbody = document.getElementById("alerts-tbody");
  tbody.innerHTML = "";
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    tr.dataset.sessionId = r.session_id;
    tr.innerHTML = `
      <td><span class="sev-badge sev-${r.severity}">${r.severity}</span></td>
      <td class="mono">${r.session_id.slice(0, 8)}…</td>
      <td>${r.scenario.replace(/_/g, " ")}</td>
      <td class="mono">${r.risk_score.toFixed(3)}</td>
      <td>${r.detection_reason || "—"}</td>
      <td>${r.ground_truth_label}</td>
    `;
    tr.addEventListener("click", () => selectSession(r.session_id, tr));
    tbody.appendChild(tr);
  });
}

async function selectSession(sessionId, trEl) {
  document.querySelectorAll(".alerts-table tbody tr").forEach((r) => r.classList.remove("selected"));
  if (trEl) trEl.classList.add("selected");
  state.selectedSession = sessionId;

  const res = await fetch(`/api/session/${sessionId}?mode=${state.mode}&dataset=${state.dataset}`);
  const d = await res.json();

  document.getElementById("detail-empty").classList.add("hidden");
  document.getElementById("detail-content").classList.remove("hidden");

  document.getElementById("d-session-id").textContent = d.alert.session_id;
  document.getElementById("d-scenario").textContent = (d.alert.scenario || "").replace(/_/g, " ");
  document.getElementById("d-risk").textContent = Number(d.alert.risk_score || 0).toFixed(3);

  const subEl = document.getElementById("d-subscores");
  subEl.innerHTML = "";
  const chips = [
    ["Driver hash match", !!d.alert.rule_match],
    ["Privilege escalation", !!d.alert.privilege_escalation_flag],
    ["Security process killed", !!d.alert.security_process_killed],
    [`Precursor commands: ${d.alert.precursor_command_count || 0}`, (d.alert.precursor_command_count || 0) > 0],
    ["Burst alert (<5s)", !!d.alert.burst_alert],
  ];
  chips.forEach(([label, on]) => {
    const chip = document.createElement("span");
    chip.className = "chip" + (on ? " on" : "");
    chip.textContent = label;
    subEl.appendChild(chip);
  });

  const tl = document.getElementById("d-timeline");
  tl.innerHTML = "";
  d.events.forEach((e) => {
    const item = document.createElement("div");
    item.className = "timeline-item";
    const t = e.timestamp ? e.timestamp.split("T")[1]?.split(".")[0] || e.timestamp : "";
    item.innerHTML = `
      <div class="timeline-body" style="flex:1">
        <div class="timeline-label">${e.label} <span class="timeline-time">${t}</span></div>
        ${e.detail ? `<div class="timeline-detail">${escapeHtml(e.detail)}</div>` : ""}
      </div>
    `;
    tl.appendChild(item);
  });

  const mitreEl = document.getElementById("d-mitre");
  mitreEl.innerHTML = "";
  if (d.mitre.length === 0) {
    mitreEl.innerHTML = `<div class="muted small">No MITRE techniques matched this session.</div>`;
  } else {
    d.mitre.forEach((m) => {
      const tag = document.createElement("div");
      tag.className = "mitre-tag";
      tag.innerHTML = `<b>${m.technique_id}</b> — ${m.technique_name}`;
      mitreEl.appendChild(tag);
    });
  }

  document.getElementById("d-download-report").onclick = () => {
    window.location.href = `/api/report/${sessionId}?mode=${state.mode}&dataset=${state.dataset}`;
  };
}

async function loadMitre() {
  const res = await fetch(`/api/alerts?mode=${state.mode}&dataset=${state.dataset}&only_alerts=true`);
  const rows = await res.json();
  const mapKeys = {
    rule_match: { technique_id: "T1068", technique_name: "Exploitation for Privilege Escalation (via vulnerable driver / BYOVD)" },
    privilege_escalation_flag: { technique_id: "T1543.003", technique_name: "Create or Modify System Process: Windows Service (kernel-level access via loaded driver)" },
    security_process_killed: { technique_id: "T1562.001", technique_name: "Impair Defenses: Disable or Modify Tools" },
    precursor_command_count: { technique_id: "T1490", technique_name: "Inhibit System Recovery" },
  };

  const grid = document.getElementById("mitre-grid");
  grid.innerHTML = "";
  Object.entries(mapKeys).forEach(([key, tech]) => {
    const count = rows.filter((r) => (key === "precursor_command_count" ? r[key] > 0 : r[key] === true)).length;
    const card = document.createElement("div");
    card.className = "mitre-card";
    card.innerHTML = `
      <div class="mitre-card-id">${tech.technique_id}</div>
      <div class="mitre-card-name">${tech.technique_name}</div>
      <div><span class="mitre-card-count">${count}</span><span class="mitre-card-count-label">alerted sessions</span></div>
    `;
    grid.appendChild(card);
  });
}

async function loadCompare() {
  const res = await fetch(`/api/compare?dataset=${state.dataset}`);
  const d = await res.json();
  const labels = ["hybrid", "rule_only", "ml_only"];
  const prettyLabels = ["Hybrid", "Rule-only", "ML-only"];
  const precision = labels.map((m) => (d[m] ? d[m].precision * 100 : 0));
  const recall = labels.map((m) => (d[m] ? d[m].recall * 100 : 0));

  const ctx = document.getElementById("chart-compare");
  if (compareChart) compareChart.destroy();
  compareChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: prettyLabels,
      datasets: [
        { label: "Precision %", data: precision, backgroundColor: "#22D3B8", borderRadius: 4 },
        { label: "Recall %", data: recall, backgroundColor: "#F2A93C", borderRadius: 4 },
      ],
    },
    options: {
      plugins: {
        legend: { labels: { color: "#8D97B8", font: { family: "IBM Plex Sans", size: 12 } } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { color: "#E7ECF8", font: { family: "Space Grotesk", size: 12.5 } } },
        y: { grid: { color: "#1B2740" }, ticks: { color: "#8D97B8" }, beginAtZero: true, max: 100 },
      },
    },
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ---------------- Init ----------------

setSubtitle();
loadOverview();
