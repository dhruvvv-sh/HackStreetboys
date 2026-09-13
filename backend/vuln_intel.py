"""
vuln_intel.py
-------------
Looks up real vulnerabilities from OSV.dev (https://osv.dev) for a given
PyPI package@version. If the OSV API is unreachable (e.g. no internet in
a sandboxed environment), falls back to a DETERMINISTIC mock generator so
the rest of the pipeline (risk scoring, blast radius, dashboard) still has
something to work with. Mock findings are always clearly flagged
`"source": "mock"` so the UI can label them as demo data.
"""
import hashlib
import requests

OSV_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 6

_SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEVERITY_SCORE = {"NONE": 0, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}


def _severity_from_osv_entry(vuln: dict) -> str:
    # OSV entries carry severity in different shapes depending on the source DB.
    for sev in vuln.get("severity", []):
        score = sev.get("score", "")
        try:
            val = float(score)
            if val >= 9.0:
                return "CRITICAL"
            if val >= 7.0:
                return "HIGH"
            if val >= 4.0:
                return "MEDIUM"
            return "LOW"
        except ValueError:
            pass
    db_specific = vuln.get("database_specific", {}) or {}
    sev = (db_specific.get("severity") or "").upper()
    if sev in _SEVERITY_SCORE:
        return sev
    return "MEDIUM"  # OSV lists it, but no parseable severity -> assume medium


def query_osv(name: str, version: str) -> list[dict] | None:
    """Real OSV.dev lookup. Returns a list of findings, or None on network failure."""
    try:
        resp = requests.post(
            OSV_URL,
            json={"version": version, "package": {"name": name, "ecosystem": "PyPI"}},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        vulns = resp.json().get("vulns", [])
        findings = []
        for v in vulns:
            findings.append({
                "id": v.get("id", "UNKNOWN"),
                "summary": (v.get("summary") or v.get("details") or "")[:160],
                "severity": _severity_from_osv_entry(v),
                "fixed": _has_fix(v),
                "source": "osv.dev",
            })
        return findings
    except requests.RequestException:
        return None


def _has_fix(vuln: dict) -> bool:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return True
    return False


def _mock_findings(name: str, version: str) -> list[dict]:
    """Deterministic pseudo-random findings so a demo run is reproducible
    even with no network access. ~35% of packages get a finding."""
    h = int(hashlib.sha256(f"{name}@{version}".encode()).hexdigest(), 16)
    if h % 100 >= 35:
        return []
    severity = _SEVERITY_ORDER[1 + (h // 100) % 4]  # LOW..CRITICAL
    fixed = (h // 10) % 2 == 0
    return [{
        "id": f"MOCK-{h % 9000 + 1000}",
        "summary": f"Simulated advisory for {name} (offline demo data \u2014 no live OSV.dev connection).",
        "severity": severity,
        "fixed": fixed,
        "source": "mock",
    }]


def get_vulnerabilities(name: str, version: str) -> list[dict]:
    if version and version != "unknown":
        result = query_osv(name, version)
        if result is not None:
            return result
    return _mock_findings(name, version or "0.0.0")


def severity_score(findings: list[dict]) -> int:
    if not findings:
        return 0
    return max(_SEVERITY_SCORE.get(f["severity"], 50) for f in findings)
