import requests
import time
from config import NVD_API_URL


def fetch_cves(results_per_page=50):
    """Fetch recent CVEs from the NVD API."""
    params = {
        "resultsPerPage": results_per_page,
        "pubStartDate": "2024-01-01T00:00:00.000Z",
        "pubEndDate": "2024-04-29T23:59:59.999Z",
    }
    response = requests.get(NVD_API_URL, params=params)
    response.raise_for_status()
    return response.json()

def parse_cve_records(raw_data):
    """Parse NVD API response into documents with metadata."""
    documents = []
    vulnerabilities = raw_data.get("vulnerabilities", [])

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity = "UNKNOWN"
        cvss_score = 0.0
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            cvss_score = cvss_data.get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss_data.get("baseScore", 0.0)
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        published = cve.get("published", "")

        text = f"{cve_id}: {description} (Severity: {severity}, CVSS: {cvss_score})"

        documents.append({
            "text": text,
            "metadata": {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "published": published,
                "description": description,
            },
        })

    return documents
if __name__ == "__main__":
    print("Fetching CVEs from NVD API...")
    raw = fetch_cves(50)
    docs = parse_cve_records(raw)
    print(f"Parsed {len(docs)} CVE documents.")
    if docs:
        print(f"\nSample document:\n{docs[0]['text'][:200]}")
        print(f"Metadata: {docs[0]['metadata']}")
