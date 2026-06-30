from qdrant_client import QdrantClient
from ingest import fetch_cves, parse_cve_records
from search import create_collection, ingest_documents, hybrid_search


def test_severity_filter():
    """Test hybrid search with severity-based metadata filtering."""
    client = QdrantClient(":memory:")

    raw_data = fetch_cves(50)
    documents = parse_cve_records(raw_data)

    create_collection(client)
    ingest_documents(client, documents)

    query = "memory corruption vulnerabilities"

    print("Hybrid search WITHOUT severity filter:")
    results = hybrid_search(client, query)
    for r in results:
        print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']} - CVSS: {r.payload['cvss_score']}")

    print("\nHybrid search WITH severity_filter='CRITICAL':")
    filtered_results = hybrid_search(client, query, severity_filter="CRITICAL")
    if filtered_results:
        for r in filtered_results:
            print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']} - CVSS: {r.payload['cvss_score']}")
    else:
        print("  No CRITICAL results found. Try 'HIGH' instead.")
        filtered_results = hybrid_search(client, query, severity_filter="HIGH")
        for r in filtered_results:
            print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']} - CVSS: {r.payload['cvss_score']}")


def test_cvss_and_score_threshold_filter():
    """Test hybrid search with CVSS-based filtering and score thresholding."""
    client = QdrantClient(":memory:")

    raw_data = fetch_cves(50)
    documents = parse_cve_records(raw_data)

    create_collection(client)
    ingest_documents(client, documents)

    query = "vulnerability"

    print("\n--- Testing Min CVSS Filter ---")
    min_cvss = 7.0
    print(f"Hybrid search with min_cvss={min_cvss}:")
    cvss_results = hybrid_search(client, query, min_cvss=min_cvss, limit=10)
    if cvss_results:
        for r in cvss_results:
            print(f"  {r.payload['cve_id']} - CVSS Score: {r.payload['cvss_score']}")
            assert r.payload['cvss_score'] >= min_cvss, f"Vulnerability {r.payload['cve_id']} has CVSS {r.payload['cvss_score']} < {min_cvss}"
    else:
        print("  No results found with CVSS >= 7.0")

    print("\n--- Testing Score Threshold Filter ---")
    # Get standard results to see standard scores
    all_results = hybrid_search(client, query, limit=5)
    if all_results:
        threshold = all_results[0].score * 0.9  # slightly less than the top score
        print(f"Top score is {all_results[0].score:.4f}. Setting threshold to {threshold:.4f}")
        threshold_results = hybrid_search(client, query, score_threshold=threshold, limit=5)
        for r in threshold_results:
            print(f"  {r.payload['cve_id']} - Score: {r.score:.4f}")
            assert r.score >= threshold, f"Result {r.payload['cve_id']} has score {r.score} < {threshold}"
    else:
        print("  No standard results found to test threshold.")


if __name__ == "__main__":
    print("=== Running Severity Filter Test ===")
    test_severity_filter()
    print("\n=== Running CVSS and Score Threshold Filter Test ===")
    test_cvss_and_score_threshold_filter()

