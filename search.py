from qdrant_client import QdrantClient, models
from config import COLLECTION_NAME, DENSE_MODEL, SPARSE_MODEL


def create_collection(client, force_recreate=False):
    """Create a Qdrant collection with both dense and sparse vectors if it doesn't exist."""
    if force_recreate:
        try:
            client.delete_collection(collection_name=COLLECTION_NAME)
            print(f"Deleted existing collection '{COLLECTION_NAME}' for clean recreation.")
        except Exception as e:
            print(f"Note: Could not delete collection '{COLLECTION_NAME}' (it may not exist): {e}")

    if client.collection_exists(collection_name=COLLECTION_NAME):
        print(f"Collection '{COLLECTION_NAME}' already exists. Skipping creation.")
        return False

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config={
            "dense": models.VectorParams(
                size=384,
                distance=models.Distance.COSINE,
            ),
        },
        sparse_vectors_config={
            "sparse": models.SparseVectorParams(
                modifier=models.Modifier.IDF,
            ),
        },
    )
    print(f"Created collection '{COLLECTION_NAME}' successfully.")
    return True

def ingest_documents(client, documents):
    """Ingest documents with both dense and sparse vectors."""
    points = []
    for i, doc in enumerate(documents):
        point = models.PointStruct(
            id=i,
            vector={
                "dense": models.Document(
                    text=doc["text"],
                    model=DENSE_MODEL,
                ),
                "sparse": models.Document(
                    text=doc["text"],
                    model=SPARSE_MODEL,
                ),
            },
            payload=doc["metadata"],
        )
        points.append(point)

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"Ingested {len(points)} documents into '{COLLECTION_NAME}'.")

def build_qdrant_filter(severity_filter=None, min_cvss=None):
    """Build a Qdrant Filter object based on severity and CVSS score constraints."""
    must_conditions = []
    if severity_filter:
        must_conditions.append(
            models.FieldCondition(
                key="severity",
                match=models.MatchValue(value=severity_filter),
            )
        )
    if min_cvss is not None:
        try:
            min_cvss_val = float(min_cvss)
            if min_cvss_val > 0.0:
                must_conditions.append(
                    models.FieldCondition(
                        key="cvss_score",
                        range=models.Range(gte=min_cvss_val),
                    )
                )
        except (ValueError, TypeError):
            pass

    if must_conditions:
        return models.Filter(must=must_conditions)
    return None


def dense_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None):
    """Search using only dense (semantic) vectors."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss)
    response = client.query_points(
        collection_name=COLLECTION_NAME,
        query=models.Document(text=query, model=DENSE_MODEL),
        using="dense",
        limit=limit,
        query_filter=query_filter,
        with_payload=True,
    )
    points = response.points
    if score_threshold is not None:
        points = [p for p in points if p.score >= score_threshold]
    return points


def sparse_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None):
    """Search using only sparse (BM25) vectors."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss)
    response = client.query_points(
        collection_name=COLLECTION_NAME,
        query=models.Document(text=query, model=SPARSE_MODEL),
        using="sparse",
        limit=limit,
        query_filter=query_filter,
        with_payload=True,
    )
    points = response.points
    if score_threshold is not None:
        points = [p for p in points if p.score >= score_threshold]
    return points


def hybrid_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None):
    """Search using hybrid dense + sparse with RRF fusion."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss)

    prefetch = [
        models.Prefetch(
            query=models.Document(text=query, model=SPARSE_MODEL),
            using="sparse",
            limit=20,
            filter=query_filter,
        ),
        models.Prefetch(
            query=models.Document(text=query, model=DENSE_MODEL),
            using="dense",
            limit=20,
            filter=query_filter,
        ),
    ]

    response = client.query_points(
        collection_name=COLLECTION_NAME,
        prefetch=prefetch,
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=limit,
        with_payload=True,
    )
    points = response.points
    if score_threshold is not None:
        points = [p for p in points if p.score >= score_threshold]
    return points

