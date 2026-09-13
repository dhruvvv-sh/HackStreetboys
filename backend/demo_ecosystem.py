"""
demo_ecosystem.py
------------------
Real reverse-dependency data ("which of the world's applications use this
package") would require mirroring the entire PyPI ecosystem, which is out
of scope for a hackathon prototype. Real forward-dependency data (this repo
DEPENDS_ON these packages) comes from graph_builder.py and IS real.

To demonstrate the ripple-effect / blast-radius concept end-to-end, we
attach a small, clearly-labelled set of ILLUSTRATIVE downstream
applications on top of the real graph. Every value here is DEMO DATA,
never presented as a measurement, and the frontend always shows a
"demo data" badge next to it.
"""
import hashlib

DEMO_APPS = [
    {"name": "checkout-service", "critical": True},
    {"name": "auth-gateway", "critical": True},
    {"name": "billing-api", "critical": True},
    {"name": "search-service", "critical": False},
    {"name": "notification-worker", "critical": False},
    {"name": "admin-portal", "critical": False},
    {"name": "mobile-bff", "critical": True},
    {"name": "data-pipeline", "critical": False},
    {"name": "reporting-service", "critical": False},
    {"name": "partner-integration-api", "critical": False},
]


def attach_demo_applications(graph, seed: str = "rippleguard"):
    """
    Deterministically wires each demo app to 2-4 packages already in the
    graph, weighted toward deeper nodes (packages further from the root are
    more likely to be shared low-level utilities in a real ecosystem, which
    is exactly the "small dependency, big blast radius" story this tool is
    built to surface).

    Mutates `graph` in place, adding app nodes (type="application") and
    APP_USES_PACKAGE edges (app -> package).
    """
    nodes = list(graph.nodes)
    if not nodes:
        return graph

    depths = {n: graph.nodes[n].get("depth", 0) for n in nodes}
    max_depth = max(depths.values()) if depths else 0

    for app in DEMO_APPS:
        graph.add_node(app["name"], type="application", critical=app["critical"])
        h = int(hashlib.sha256(f"{seed}:{app['name']}".encode()).hexdigest(), 16)
        n_links = 2 + (h % 3)  # 2-4 packages per app

        # weight = deeper nodes are picked more often
        weighted = []
        for n in nodes:
            weight = 1 + depths.get(n, 0) * 2
            weighted.extend([n] * weight)

        picks = []
        idx = h
        for _ in range(n_links):
            if not weighted:
                break
            idx = (idx * 2654435761 + 1) & 0xFFFFFFFF
            pick = weighted[idx % len(weighted)]
            if pick not in picks:
                picks.append(pick)

        for pkg in picks:
            graph.add_edge(app["name"], pkg, relation="APP_USES_PACKAGE")

    return graph
