"""
graph_builder.py
-----------------
Parses a requirements.txt-style input, then builds a REAL dependency graph
by walking PyPI's JSON metadata API (https://pypi.org/pypi/<name>/json).

This is intentionally scoped for a hackathon prototype:
- depth-limited BFS (default 2 levels of transitive deps) to keep it fast
- a small in-memory cache so re-analyzing is instant
- best-effort dependency-string parsing (no hard dependency on `packaging`)

Graph convention:
  edge (A -> B) means "A DEPENDS_ON B"
  node attrs: {"version": str, "root": bool, "depth": int}
"""
import re
import time
import requests
import networkx as nx

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
REQUEST_TIMEOUT = 6
_METADATA_CACHE: dict[str, dict] = {}

# crude "name (specifier); marker" splitter for PyPI's requires_dist strings
_DEP_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)")


def _clean_name(raw: str) -> str:
    return raw.strip().lower().replace("_", "-")


def parse_requirements(text: str) -> list[str]:
    """Extract bare package names from a requirements.txt-like blob."""
    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split(";")[0]  # drop environment markers
        m = _DEP_NAME_RE.match(line)
        if m:
            names.append(_clean_name(m.group(1)))
    # de-dupe, keep order
    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def fetch_pypi_metadata(name: str) -> dict | None:
    """Fetch + cache PyPI JSON metadata for a package. Returns None on failure."""
    if name in _METADATA_CACHE:
        return _METADATA_CACHE[name]
    try:
        resp = requests.get(PYPI_JSON.format(name=name), timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            _METADATA_CACHE[name] = None
            return None
        data = resp.json()
        _METADATA_CACHE[name] = data
        return data
    except requests.RequestException:
        _METADATA_CACHE[name] = None
        return None


def _direct_deps(meta: dict) -> list[str]:
    """Pull direct runtime dependency names out of PyPI metadata, skipping
    optional 'extra ==' markers so the graph reflects a default install."""
    reqs = (meta or {}).get("info", {}).get("requires_dist") or []
    out = []
    for r in reqs:
        if "extra ==" in r or "extra==" in r:
            continue
        r = r.split(";")[0]
        m = _DEP_NAME_RE.match(r)
        if m:
            out.append(_clean_name(m.group(1)))
    return out


def build_dependency_graph(root_names: list[str], max_depth: int = 2, max_nodes: int = 60):
    """
    BFS out from the given root packages using live PyPI metadata.
    Returns (graph, meta_by_pkg, unresolved) where meta_by_pkg maps
    package name -> {"version": str, "found": bool}.
    """
    graph = nx.DiGraph()
    meta_by_pkg: dict[str, dict] = {}
    unresolved: list[str] = []

    frontier = [(n, 0) for n in root_names]
    for n in root_names:
        graph.add_node(n, root=True, depth=0)

    visited = set()
    while frontier and len(graph.nodes) < max_nodes:
        name, depth = frontier.pop(0)
        if name in visited:
            continue
        visited.add(name)

        meta = fetch_pypi_metadata(name)
        if meta is None:
            unresolved.append(name)
            meta_by_pkg[name] = {"version": "unknown", "found": False}
            continue

        version = meta.get("info", {}).get("version", "unknown")
        meta_by_pkg[name] = {"version": version, "found": True}
        if not graph.has_node(name):
            graph.add_node(name, root=False, depth=depth)
        else:
            graph.nodes[name]["depth"] = min(graph.nodes[name].get("depth", depth), depth)

        if depth >= max_depth:
            continue

        for dep in _direct_deps(meta):
            if len(graph.nodes) >= max_nodes and dep not in graph:
                continue
            graph.add_edge(name, dep)
            if dep not in visited:
                if not graph.has_node(dep) or "depth" not in graph.nodes[dep]:
                    graph.add_node(dep, root=graph.nodes[dep].get("root", False) if graph.has_node(dep) else False)
                graph.nodes[dep]["depth"] = min(graph.nodes[dep].get("depth", depth + 1), depth + 1)
                frontier.append((dep, depth + 1))

    return graph, meta_by_pkg, unresolved
