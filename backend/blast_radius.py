"""
blast_radius.py
----------------
"If this dependency is compromised, what could be affected?"

Propagates outward from a chosen package to every dependent (direct +
transitive) using the same DEPENDS_ON graph, and reports the shortest
propagation path from the compromised package to each affected application
so the UI can show *how* the impact would travel.
"""
import networkx as nx


def simulate(graph: nx.DiGraph, package: str) -> dict:
    if package not in graph:
        return {"error": f"'{package}' is not in the current dependency graph."}

    dependents = nx.ancestors(graph, package)
    affected_packages = sorted(n for n in dependents if graph.nodes[n].get("type") != "application")
    affected_apps = sorted(n for n in dependents if graph.nodes[n].get("type") == "application")
    critical_apps = [a for a in affected_apps if graph.nodes[a].get("critical")]

    # shortest propagation path (compromised package -> each affected app), reversed to read forward
    paths = {}
    for app in affected_apps:
        try:
            rev_path = nx.shortest_path(graph, source=app, target=package)
            paths[app] = list(reversed(rev_path))
        except nx.NetworkXNoPath:
            continue

    total_affected = len(affected_packages) + len(affected_apps)
    if len(critical_apps) >= 2 or total_affected >= 10:
        risk_level = "CRITICAL"
    elif len(critical_apps) >= 1 or total_affected >= 5:
        risk_level = "HIGH"
    elif total_affected >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    most_exposed = sorted(
        affected_packages,
        key=lambda n: len(nx.ancestors(graph, n)),
        reverse=True,
    )[:5]

    return {
        "compromised_package": package,
        "affected_package_count": len(affected_packages),
        "affected_app_count": len(affected_apps),
        "critical_apps_affected": critical_apps,
        "affected_packages": affected_packages,
        "affected_apps": affected_apps,
        "propagation_paths": paths,
        "most_exposed_components": most_exposed,
        "risk_level": risk_level,
    }
