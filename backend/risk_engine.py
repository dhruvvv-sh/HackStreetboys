"""
risk_engine.py
--------------
Combines two dimensions on purpose, per the project brief:
  1. SECURITY RISK       -- how dangerous is the vulnerability itself (OSV/mock)
  2. STRUCTURAL RISK     -- how important is this package in the dependency graph

This is a prioritization heuristic, not a certified/scientific formula.
Weights are simple and documented so judges can see exactly how a number
was produced (no black box).
"""
import networkx as nx

WEIGHTS = {"severity": 0.35, "structural": 0.30, "downstream_apps": 0.20, "exposure": 0.15}


def dependents_of(graph: nx.DiGraph, node: str) -> set:
    """Every node with a directed path TO `node` -- i.e. everything that
    depends on it, directly or transitively (packages and demo apps)."""
    if node not in graph:
        return set()
    return nx.ancestors(graph, node)


def score_package(graph: nx.DiGraph, node: str, findings: list[dict], severity_score: int) -> dict:
    dependents = dependents_of(graph, node)
    package_dependents = [n for n in dependents if graph.nodes[n].get("type") != "application"]
    app_dependents = [n for n in dependents if graph.nodes[n].get("type") == "application"]
    critical_apps = [n for n in app_dependents if graph.nodes[n].get("critical")]

    structural_score = min(100, len(package_dependents) * 12)
    downstream_apps_score = min(100, len(app_dependents) * 18)

    if not findings:
        exposure_score = 0
    elif any(not f.get("fixed") for f in findings):
        exposure_score = 100
    else:
        exposure_score = 35  # vulnerable, but a fix already exists

    ecosystem_risk = round(
        WEIGHTS["severity"] * severity_score
        + WEIGHTS["structural"] * structural_score
        + WEIGHTS["downstream_apps"] * downstream_apps_score
        + WEIGHTS["exposure"] * exposure_score
    )

    return {
        "package": node,
        "ecosystem_risk": min(100, ecosystem_risk),
        "severity_score": severity_score,
        "structural_score": structural_score,
        "downstream_apps_score": downstream_apps_score,
        "exposure_score": exposure_score,
        "downstream_package_count": len(package_dependents),
        "downstream_app_count": len(app_dependents),
        "critical_apps_affected": critical_apps,
        "findings": findings,
        "is_structural_single_point_of_failure": len(package_dependents) >= 4 and len(findings) == 0,
    }
