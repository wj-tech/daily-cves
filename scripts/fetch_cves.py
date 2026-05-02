import requests
from datetime import datetime, timedelta, timezone


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MIN_CVSS_SCORE = 7.0


# Maps CWE IDs to likely IOC types for that vulnerability class
IOC_TEMPLATES = {
    "CWE-89":  ["SQL syntax strings in HTTP parameters or logs",
                "Excessive database error responses (500s)",
                "Unusual database query volumes or timings"],
    "CWE-79":  ["Script tags or encoded JS in user-supplied input",
                "Unexpected outbound requests from client browsers",
                "CSP violation reports"],
    "CWE-78":  ["Unexpected child processes spawned by the web/app server",
                "Unusual system command executions in OS audit logs",
                "New cron jobs or scheduled tasks"],
    "CWE-22":  ["Directory traversal sequences (../) in request paths",
                "Access to files outside expected document root in logs"],
    "CWE-434": ["Unexpected file types uploaded to the server",
                "New executable files in upload directories",
                "Unexpected outbound connections from upload directories"],
    "CWE-287": ["Authentication bypass attempts in access logs",
                "Logins without corresponding credential validation events",
                "Sessions created without prior authentication events"],
    "CWE-798": ["Successful logins from unexpected IPs using default credentials",
                "Brute-force attempts against known default accounts"],
    "CWE-502": ["Malformed or unexpected serialized objects in requests",
                "Unexpected object instantiation or class-loading in app logs"],
    "CWE-611": ["XXE payloads (<!ENTITY) in XML input",
                "Unexpected outbound DNS or HTTP from the XML parser process"],
    "CWE-94":  ["Unexpected code execution events in app logs",
                "New processes spawned by the application runtime"],
    "CWE-20":  ["Malformed or oversized input in application logs",
                "Validation error spikes in application metrics"],
    "CWE-416": ["Heap corruption indicators in crash/core dumps",
                "Unexpected memory access violations in system logs"],
    "CWE-125": ["Out-of-bounds read signals in crash reports",
                "Application crashes or unexpected exits"],
    "CWE-190": ["Integer overflow conditions in application error logs",
                "Unexpected large numeric values in request parameters"],
}

GENERIC_IOCS = [
    "Unexpected outbound network connections from the affected service",
    "Unusual process creation or privilege escalation events",
    "New or modified files in application directories",
    "Spike in error rates or application crashes around the affected component",
]


def _get_cvss(cve: dict) -> tuple[float | None, str]:
    """Return (score, severity) preferring CVSSv3.1 > v3.0 > v2."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", "")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        return data.get("baseScore"), data.get("baseSeverity", "")
    return None, ""


def _get_description(cve: dict) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "No description available.")
    return "No description available."


def _get_cwes(cve: dict) -> list[str]:
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


def _get_affected(cve: dict) -> list[str]:
    seen, results = set(), []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria", "")
                parts = uri.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    version = parts[5] if len(parts) > 5 and parts[5] not in ("*", "-") else ""
                    label = f"{vendor} {product}" + (f" {version}" if version else "")
                    if label not in seen:
                        seen.add(label)
                        results.append(label)
    return results[:10]  # cap for readability


def _get_references(cve: dict) -> list[dict]:
    refs = []
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", [])
        refs.append({"url": url, "tags": tags})
    return refs


def _build_iocs(cwes: list[str]) -> list[str]:
    iocs = []
    for cwe in cwes:
        iocs.extend(IOC_TEMPLATES.get(cwe, []))
    if not iocs:
        iocs = GENERIC_IOCS
    return list(dict.fromkeys(iocs))


def fetch_cves(days_back: int = 1) -> list[dict]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days_back)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }

    resp = requests.get(NVD_API_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        score, severity = _get_cvss(cve)
        if score is None or score < MIN_CVSS_SCORE:
            continue

        cve_id = cve.get("id", "UNKNOWN")
        cwes = _get_cwes(cve)
        results.append({
            "id": cve_id,
            "score": score,
            "severity": severity,
            "description": _get_description(cve),
            "cwes": cwes,
            "affected": _get_affected(cve),
            "references": _get_references(cve),
            "iocs": _build_iocs(cwes),
            "published": cve.get("published", ""),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return sorted(results, key=lambda x: x["score"], reverse=True)


if __name__ == "__main__":
    import json
    cves = fetch_cves()
    print(json.dumps(cves, indent=2))
    print(f"\nTotal CVEs with CVSS >= {MIN_CVSS_SCORE}: {len(cves)}")
