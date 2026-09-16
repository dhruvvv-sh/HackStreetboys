const el = (id) => document.getElementById(id);

let network = null;
let currentData = null;

function riskColor(score) {
  if (score >= 75) return "#C62828";
  if (score >= 50) return "#E88A00";
  if (score >= 25) return "#F2C94C";
  return "#4CAF50";
}

el("sampleBtn").addEventListener("click", () => {
  el("reqInput").value =
    "flask==2.3.3\nrequests==2.31.0\njinja2==3.1.2\nclick==8.1.7\nwerkzeug==2.3.7";
});

el("analyzeBtn").addEventListener("click", analyze);

async function analyze() {
  const text = el("reqInput").value.trim();
  if (!text) {
    el("statusText").textContent = "Paste at least one package requirement to start.";
    return;
  }
  el("statusText").textContent = "Analyzing PyPI dependencies and OSV findings...";
  el("analyzeBtn").disabled = true;
  try {
    const resp = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ requirements_text: text, max_depth: Number(el("depthSelect").value) }),
    });
    const data = await resp.json();
    if (data.error) {
      el("statusText").textContent = data.error;
      return;
    }
    currentData = data;
    render(data);
    el("statusText").textContent = data.unresolved.length
      ? `Analysis complete. Unresolved on PyPI: ${data.unresolved.join(", ")}`
      : "Analysis complete.";
  } catch (e) {
    el("statusText").textContent = "Request failed: " + e;
  } finally {
    el("analyzeBtn").disabled = false;
  }
}

function render(data) {
  el("dashboard").classList.remove("hidden");
  el("statOverall").textContent = data.summary.overall_risk;
  el("statCritical").textContent = data.summary.critical_dependency_count;
  el("statVulnerable").textContent = data.summary.vulnerable_package_count;
  el("statApps").textContent = data.summary.potentially_affected_apps;

  try {
    renderGraph(data);
  } catch (e) {
    console.error("Graph rendering failed:", e);
    el("network").innerHTML =
      "<p class='muted' style='padding:16px'>Graph visualization library failed to load. The rest of the dashboard (risk scores, remediation list) still works.</p>";
  }
  renderCriticalList(data);
  renderRemediation(data);
  el("blastPanel").classList.add("hidden");
  el("detailCard").innerHTML =
    "<h3>Select a package</h3><p class='muted'>Click a package node to inspect its risk score, findings, and downstream exposure.</p>";
}

function renderGraph(data) {
  const nodes = data.nodes.map((n) => {
    if (n.type === "application") {
      return {
        id: n.id,
        label: n.id,
        shape: "box",
        color: { background: n.critical ? "#0097A7" : "#8FCDD4", border: "#00707d" },
        font: { color: "white", size: 11 },
      };
    }
    const color = n.vulnerable ? riskColor(Math.max(n.ecosystem_risk, 50)) : riskColor(n.ecosystem_risk);
    return {
      id: n.id,
      label: n.id + (n.root ? " \u2605" : ""),
      shape: "dot",
      size: 10 + Math.min(20, n.ecosystem_risk / 4),
      color: { background: color, border: "#20124D" },
      font: { color: "#20124D", size: 12 },
    };
  });
  const edges = data.edges.map((e) => ({ from: e.source, to: e.target, arrows: "to", color: { color: "#cfc6ea" } }));

  const container = el("network");
  network = new vis.Network(
    container,
    { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) },
    {
      physics: { stabilization: true, barnesHut: { gravitationalConstant: -4000, springLength: 90 } },
      interaction: { hover: true },
    }
  );

  network.on("click", (params) => {
    if (!params.nodes.length) return;
    const id = params.nodes[0];
    const nodeInfo = data.nodes.find((n) => n.id === id);
    if (!nodeInfo || nodeInfo.type === "application") return;
    showDetail(id, data);
  });
}

function pill(score) {
  return `<span class="risk-pill" style="background:${riskColor(score)}">${score}</span>`;
}

function showDetail(pkgId, data) {
  const risk = (currentData.critical_dependencies.concat(currentData.remediation_priority))
    .find((r) => r.package === pkgId) || findFullRisk(pkgId);
  if (!risk) return;

  let findingsHtml = "";
  if (risk.findings && risk.findings.length) {
    findingsHtml = risk.findings
      .map(
        (f) => `<div class="finding ${f.severity.toLowerCase()}">
          <b>${f.id}</b> \u2014 ${f.severity}${f.fixed ? " (fix available)" : " (no fix yet)"}
          ${f.source === "mock" ? '<span class="demo-badge">demo</span>' : ""}
          <div>${f.summary}</div>
        </div>`
      )
      .join("");
  } else {
    findingsHtml = "<p class='muted'>No known vulnerabilities were found for this package/version.</p>";
  }

  el("detailCard").innerHTML = `
    <h3>${pkgId} <span class="muted">v${risk.version || "?"}</span></h3>
    <div class="detail-row"><span>Ecosystem risk</span>${pill(risk.ecosystem_risk)}</div>
    <div class="detail-row"><span>Vulnerability severity</span><strong>${risk.severity_score}</strong></div>
    <div class="detail-row"><span>Graph importance</span><strong>${risk.structural_score}</strong></div>
    <div class="detail-row"><span>Application reach</span><strong>${risk.downstream_apps_score}</strong></div>
    <div class="detail-row"><span>Downstream packages</span><strong>${risk.downstream_package_count}</strong></div>
    <div class="detail-row"><span>Downstream apps</span><strong>${risk.downstream_app_count} <span class="demo-badge">demo</span></strong></div>
    ${risk.is_structural_single_point_of_failure ? "<div class='finding'>\u26A0 Structural single point of failure \u2014 many dependents, currently no known CVE.</div>" : ""}
    ${findingsHtml}
    <button class="sim-btn" onclick="simulate('${pkgId}')">Simulate blast radius</button>
  `;
}

function findFullRisk(pkgId) {
  // remediation_priority / critical_dependencies are top-N only; refetch full list via graph endpoint fields on nodes if needed
  return currentData.remediation_priority.find((r) => r.package === pkgId);
}

function renderCriticalList(data) {
  const container = el("criticalList");
  if (!data.critical_dependencies.length) {
    container.innerHTML = "<p class='muted'>No dependencies crossed the critical threshold (risk \u2265 60) this run.</p>";
    return;
  }
  container.innerHTML = data.critical_dependencies
    .map(
      (r) => `<div class="list-item" onclick="focusNode('${r.package}')">
        <span>${r.package}</span>${pill(r.ecosystem_risk)}
      </div>`
    )
    .join("");
}

function renderRemediation(data) {
  const tbody = document.querySelector("#remediationTable tbody");
  tbody.innerHTML = data.remediation_priority
    .map((r, i) => {
      const why = r.findings.length
        ? `${r.findings[0].severity} vuln, ${r.downstream_package_count} deps + ${r.downstream_app_count} apps`
        : r.is_structural_single_point_of_failure
        ? `Structural single point of failure`
        : `${r.downstream_package_count} downstream deps`;
      return `<tr>
        <td>PRIORITY ${i + 1}</td>
        <td><a href="#" onclick="focusNode('${r.package}');return false;">${r.package}</a></td>
        <td>${pill(r.ecosystem_risk)}</td>
        <td>${why}</td>
        <td>${r.downstream_package_count} pkgs, ${r.downstream_app_count} apps</td>
      </tr>`;
    })
    .join("");
}

function focusNode(id) {
  if (network) {
    network.focus(id, { scale: 1.3, animation: true });
    network.selectNodes([id]);
  }
  showDetail(id, currentData);
  document.querySelector(".graph-panel").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function simulate(pkgId) {
  el("blastPanel").classList.remove("hidden");
  el("blastTitle").textContent = `Blast radius if "${pkgId}" is compromised`;
  el("blastBody").innerHTML = "<p class='muted'>Running simulation...</p>";
  const resp = await fetch("/api/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: pkgId }),
  });
  const r = await resp.json();
  if (r.error) {
    el("blastBody").innerHTML = `<p class='muted'>${r.error}</p>`;
    return;
  }

  const pathsHtml = Object.entries(r.propagation_paths)
    .map(([app, path]) => `<div class="path-item">${path.join(" \u2192 ")} \u2192 <b>${app}</b></div>`)
    .join("") || "<p class='muted'>No demo applications are downstream of this package.</p>";

  el("blastBody").innerHTML = `
    <div class="blast-grid">
      <div class="blast-stat"><b>${r.affected_package_count}</b>Affected packages</div>
      <div class="blast-stat"><b>${r.affected_app_count}</b>Affected applications <span class="demo-badge">demo</span></div>
      <div class="blast-stat"><b>${r.critical_apps_affected.length}</b>Critical services affected <span class="demo-badge">demo</span></div>
      <div class="blast-stat"><b>${r.risk_level}</b>Propagation risk level</div>
    </div>
    <h4 style="margin-bottom:4px;">Most exposed downstream components</h4>
    <p>${r.most_exposed_components.join(", ") || "None"}</p>
    <h4 style="margin-bottom:4px;">Propagation paths to affected applications</h4>
    ${pathsHtml}
  `;

  // highlight affected nodes on the graph
  if (network) {
    const updates = [];
    [...r.affected_packages, ...r.affected_apps, r.compromised_package].forEach((id) => {
      updates.push({ id, borderWidth: 3, color: { border: "#C62828" } });
    });
    network.body.data.nodes.update(updates.filter((u) => network.body.data.nodes.get(u.id)));
  }
}
