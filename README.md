# RippleGuard \u2014 Hackathon Prototype (PS-007)

A working prototype of the ecosystem-level supply-chain risk platform described
in the pitch deck. Paste a Python `requirements.txt`, and it will:

1. **Ingest** the direct dependencies you provide.
2. **Build a real dependency graph** by walking PyPI's public JSON metadata
   API (`pypi.org/pypi/<name>/json`) out to a configurable transitive depth.
3. **Overlay real vulnerability intelligence** from [OSV.dev](https://osv.dev).
4. **Score ecosystem risk** per package (severity + structural importance +
   downstream reach + patch exposure) \u2014 not just raw CVSS.
5. Let you **simulate a blast radius**: pick any package and see everything
   that would be affected if it were compromised, including the shortest
   propagation path to each affected application.
6. Rank a **remediation priority list** by ecosystem impact, not just
   severity.

## What's real vs. demo data

- **Dependency graph** (packages depending on packages): real, fetched live
  from PyPI for whatever you paste in.
- **Vulnerabilities**: real, fetched live from OSV.dev. If OSV.dev is
  unreachable (offline / sandboxed environment), the app falls back to a
  deterministic mock generator so the demo still runs \u2014 those findings are
  always labeled `"source": "mock"` and flagged in the UI.
- **Downstream "applications"** (e.g. `checkout-service`, `auth-gateway`):
  illustrative demo data, clearly badged in the UI. Real reverse-dependency
  data (which of the world's actual applications use a given package) would
  require mirroring the whole PyPI ecosystem, which is out of scope for a
  hackathon prototype. This layer exists purely to demonstrate the
  blast-radius / ecosystem-reach concept end-to-end.

No statistic in this prototype is presented as a real-world measurement
unless it says so.

## Running it

```bash
cd rippleguard
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Then open **http://localhost:8000** and either paste your own
`requirements.txt` content or click **"Load sample project"**.

## Project layout

```
backend/
  graph_builder.py    # PyPI-backed dependency graph (real)
  vuln_intel.py        # OSV.dev lookups + offline mock fallback
  demo_ecosystem.py     # illustrative downstream-application layer (demo)
  risk_engine.py        # ecosystem risk scoring
  blast_radius.py       # compromise propagation simulator
  main.py                # FastAPI app / endpoints
frontend/
  index.html, app.js, styles.css   # dashboard (vis-network graph)
sample_data/
  sample-requirements.txt
```

## Known limitations (by design, for a hackathon-scope MVP)

- Single repository / single manifest at a time (no multi-repo or org-wide
  graphs yet \u2014 that's the Phase 4+ roadmap item).
- PyPI/Python only in this prototype; `package.json`, `pom.xml`, `go.mod`,
  and SBOM ingestion are parsed the same conceptual way but not yet wired up.
- Transitive resolution is depth-limited (default 2 hops) and doesn't do
  full version-constraint solving \u2014 it's a structural approximation, good
  enough to demonstrate the graph and the risk story, not a replacement for
  a real resolver like `pip-compile`.
- Risk score is an intentionally transparent, tunable heuristic (weights are
  in `risk_engine.py`), not a certified or scientific formula.
