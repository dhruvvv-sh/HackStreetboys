"""
main.py
-------
RippleGuard prototype API.

Pipeline per the pitch deck:
  ingest -> dependency graph -> vulnerability intelligence -> risk analysis
  -> blast-radius simulator -> dashboard + remediation priority

Run with:  uvicorn backend.main:app --reload --port 8000
Then open  http://localhost:8000
"""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import blast_radius, demo_ecosystem, graph_builder, risk_engine, vuln_intel

app = FastAPI(title="RippleGuard", version="0.1.0")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# in-memory "session" -- fine for a single-user hackathon demo
STATE: dict = {"graph": None, "risk_by_package": {}, "unresolved": []}


class AnalyzeRequest(BaseModel):
    requirements_text: str
    max_depth: int = 2


class SimulateRequest(BaseModel):
    package: str


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    roots = graph_builder.parse_requirements(req.requirements_text)
    if not roots:
        return {"error": "No package names found in the supplied requirements text."}

    graph, meta_by_pkg, unresolved = graph_builder.build_dependency_graph(
        roots, max_depth=max(1, min(req.max_depth, 3))
    )
    demo_ecosystem.attach_demo_applications(graph)

    risk_by_package = {}
    for pkg, meta in meta_by_pkg.items():
        findings = vuln_intel.get_vulnerabilities(pkg, meta["version"])
        sev = vuln_intel.severity_score(findings)
        risk_by_package[pkg] = risk_engine.score_package(graph, pkg, findings, sev)
        risk_by_package[pkg]["version"] = meta["version"]
        risk_by_package[pkg]["resolved"] = meta["found"]

    STATE["graph"] = graph
    STATE["risk_by_package"] = risk_by_package
    STATE["unresolved"] = unresolved

    return _build_dashboard_payload(roots)


@app.get("/api/graph")
def get_graph():
    if STATE["graph"] is None:
        return {"error": "No analysis has been run yet. POST /api/analyze first."}
    return _build_dashboard_payload([])


@app.post("/api/simulate")
def simulate(req: SimulateRequest):
    if STATE["graph"] is None:
        return {"error": "No analysis has been run yet. POST /api/analyze first."}
    return blast_radius.simulate(STATE["graph"], req.package)


def _build_dashboard_payload(roots: list[str]) -> dict:
    graph = STATE["graph"]
    risk_by_package = STATE["risk_by_package"]

    nodes = []
    for n in graph.nodes:
        is_app = graph.nodes[n].get("type") == "application"
        entry = {
            "id": n,
            "type": "application" if is_app else "package",
            "root": graph.nodes[n].get("root", False),
        }
        if is_app:
            entry["critical"] = graph.nodes[n].get("critical", False)
        else:
            r = risk_by_package.get(n, {})
            entry["ecosystem_risk"] = r.get("ecosystem_risk", 0)
            entry["version"] = r.get("version", "unknown")
            entry["vulnerable"] = bool(r.get("findings"))
        nodes.append(entry)

    edges = [{"source": u, "target": v} for u, v in graph.edges]

    package_risks = [r for r in risk_by_package.values()]
    vulnerable = [r for r in package_risks if r["findings"]]
    critical_dependencies = sorted(
        [r for r in package_risks if r["ecosystem_risk"] >= 60],
        key=lambda r: r["ecosystem_risk"],
        reverse=True,
    )
    remediation_priority = sorted(package_risks, key=lambda r: r["ecosystem_risk"], reverse=True)[:10]

    affected_apps = set()
    for r in vulnerable:
        affected_apps.update(risk_engine.dependents_of(graph, r["package"]))
    affected_apps = {a for a in affected_apps if graph.nodes[a].get("type") == "application"}

    overall_risk = round(sum(r["ecosystem_risk"] for r in package_risks) / len(package_risks)) if package_risks else 0

    return {
        "roots": roots,
        "nodes": nodes,
        "edges": edges,
        "unresolved": STATE["unresolved"],
        "summary": {
            "overall_risk": overall_risk,
            "critical_dependency_count": len(critical_dependencies),
            "vulnerable_package_count": len(vulnerable),
            "potentially_affected_apps": len(affected_apps),
            "total_packages": len(package_risks),
        },
        "critical_dependencies": critical_dependencies,
        "remediation_priority": remediation_priority,
    }
