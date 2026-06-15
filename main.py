from qdrant_client import QdrantClient
from groq import Groq
from config import GROQ_API_KEY, GROQ_MODEL, COLLECTION_NAME
from ingest import fetch_cves, parse_cve_records
from search import create_collection, ingest_documents, dense_search, sparse_search, hybrid_search

def compare_strategies(client, query):
    """Compare all three retrieval strategies on a query."""
    print(f"\n{'='*60}")
    print(f"Query: {query}")
    print(f"{'='*60}")

    # Run all three search strategies
    dense_results = dense_search(client, query)
    sparse_results = sparse_search(client, query)
    hybrid_results = hybrid_search(client, query)

    # Print top 3 from each strategy
    print(f"\nDense (semantic) results:")
    for r in dense_results[:3]:
        print(f"  [{r.score:.3f}] {r.payload['cve_id']} - {r.payload['severity']}")

    print(f"\nSparse (BM25) results:")
    for r in sparse_results[:3]:
        print(f"  [{r.score:.3f}] {r.payload['cve_id']} - {r.payload['severity']}")

    print(f"\nHybrid (RRF) results:")
    for r in hybrid_results[:3]:
        print(f"  [{r.score:.3f}] {r.payload['cve_id']} - {r.payload['severity']}")

    return hybrid_results
def generate_answer(groq_client, query, context_docs):
    """Generate a grounded answer using Groq."""
    # Format retrieved documents as context for the LLM
    context = "\n\n".join(
        f"- {doc.payload['cve_id']}: {doc.payload['description']} "
        f"(Severity: {doc.payload['severity']}, CVSS: {doc.payload['cvss_score']})"
        for doc in context_docs
    )

    # Build the prompt with system instructions and user query
    messages = [
        {
            "role": "system",
            "content": (
                "You are a security vulnerability analyst. Answer questions "
                "based ONLY on the provided CVE context. If the context does not "
                "contain relevant information, say so. Cite CVE IDs in your response."
            ),
        },
        {
            "role": "user",
            "content": f"Context:\n{context}\n\nQuestion: {query}",
        },
    ]

    # Call Groq with low temperature for factual answers
    response = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=messages,
        temperature=0.1,
        max_tokens=500,
    )
    return response.choices[0].message.content

def main():
    print("Initializing Qdrant (in-memory)...")
    client = QdrantClient(":memory:")

    print("Fetching CVE data from NVD...")
    raw_data = fetch_cves(50)
    documents = parse_cve_records(raw_data)
    print(f"Loaded {len(documents)} CVE records.")

    print("Creating hybrid collection and ingesting documents...")
    create_collection(client)
    ingest_documents(client, documents)

    # Test with three query types: exact ID, semantic, and technical
    test_queries = [
        documents[0]["metadata"]["cve_id"],
        "remote code execution in web servers",
        "memory corruption buffer overflow vulnerability",
    ]

    for query in test_queries:
        compare_strategies(client, query)
    
    print("\n\nGenerating vulnerability report with Groq...")
    print("API key exists:", bool(GROQ_API_KEY))
    print("Starts with gsk_:", GROQ_API_KEY.startswith("gsk_"))
    print("Length:", len(GROQ_API_KEY))
    groq_client = Groq(api_key=GROQ_API_KEY)
    query = "What are the most critical vulnerabilities?"
    results = hybrid_search(client, query, severity_filter="CRITICAL")
    if not results:
        results = hybrid_search(client, query)

    answer = generate_answer(groq_client, query, results)
    print(f"\nQuery: {query}")
    print(f"\nAnswer:\n{answer}")

if __name__ == "__main__":
    main()



