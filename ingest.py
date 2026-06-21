import os
import json
from datetime import datetime, timedelta
import requests
import time
from config import NVD_API_URL, CVE_CACHE_FILE, CACHE_EXPIRY_HOURS


def fetch_cves(results_per_page=50, force_refresh=False, days=90):
    """Fetch recent CVEs from the NVD API with local caching."""
    # Check cache first
    cache_exists = os.path.exists(CVE_CACHE_FILE)
    if cache_exists and not force_refresh:
        try:
            with open(CVE_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
            
            timestamp = cache_data.get("timestamp", 0)
            cached_params = cache_data.get("params", {})
            
            # Check if cache is still fresh and parameters match
            cache_age = (time.time() - timestamp) / 3600.0
            if cache_age < CACHE_EXPIRY_HOURS and cached_params.get("resultsPerPage") == results_per_page:
                print(f"Loading CVEs from local cache (cached {cache_age:.1f} hours ago)...")
                return cache_data["data"]
        except Exception as e:
            print(f"Warning: Failed to read cache file ({e}). Re-fetching...")

    # Calculate dynamic dates (UTC)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    params = {
        "resultsPerPage": results_per_page,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.999Z"),
    }
    
    print(f"Fetching from NVD API ({start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')})...")
    
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        # Save to cache
        try:
            with open(CVE_CACHE_FILE, "w") as f:
                json.dump({
                    "timestamp": time.time(),
                    "params": params,
                    "data": data
                }, f, indent=2)
            print("Successfully cached fetched CVEs.")
        except Exception as e:
            print(f"Warning: Failed to write cache file ({e}).")
            
        return data
        
    except Exception as e:
        print(f"Error fetching from NVD API: {e}")
        if cache_exists:
            print("Using expired local cache as fallback...")
            try:
                with open(CVE_CACHE_FILE, "r") as f:
                    cache_data = json.load(f)
                return cache_data["data"]
            except Exception as cache_err:
                print(f"Critical error: Failed to read fallback cache ({cache_err}).")
        raise e


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
