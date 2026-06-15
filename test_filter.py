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
        print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']}")

    print("\nHybrid search WITH severity_filter='CRITICAL':")
    filtered_results = hybrid_search(client, query, severity_filter="CRITICAL")
    if filtered_results:
        for r in filtered_results:
            print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']}")
    else:
        print("  No CRITICAL results found. Try 'HIGH' instead.")
        filtered_results = hybrid_search(client, query, severity_filter="HIGH")
        for r in filtered_results:
            print(f"  {r.payload['cve_id']} - Severity: {r.payload['severity']}")


if __name__ == "__main__":
    test_severity_filter()
