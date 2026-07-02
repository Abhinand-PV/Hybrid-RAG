from datetime import datetime
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

def ingest_documents(client, documents, batch_size=100):
    """Ingest documents in batches with both dense and sparse vectors."""
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

    total_points = len(points)
    for idx in range(0, total_points, batch_size):
        batch = points[idx:idx + batch_size]
        client.upsert(collection_name=COLLECTION_NAME, points=batch)
        print(f"Ingested batch {idx // batch_size + 1}/{(total_points + batch_size - 1) // batch_size} ({len(batch)} points) into '{COLLECTION_NAME}'.")

    print(f"Successfully ingested all {total_points} documents into '{COLLECTION_NAME}'.")

def build_qdrant_filter(severity_filter=None, min_cvss=None, start_date=None, end_date=None):
    """Build a Qdrant Filter object based on severity, CVSS score constraints, and date ranges."""
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

    if start_date or end_date:
        range_args = {}
        if start_date:
            val = start_date.strip()
            if len(val) == 10 and val.count("-") == 2:
                val += "T00:00:00Z"
            try:
                dt = datetime.fromisoformat(val.replace("Z", ""))
                range_args["gte"] = dt.timestamp()
            except Exception:
                pass
        if end_date:
            val = end_date.strip()
            if len(val) == 10 and val.count("-") == 2:
                val += "T23:59:59Z"
            try:
                dt = datetime.fromisoformat(val.replace("Z", ""))
                range_args["lte"] = dt.timestamp()
            except Exception:
                pass

        if range_args:
            must_conditions.append(
                models.FieldCondition(
                    key="published_timestamp",
                    range=models.Range(**range_args),
                )
            )

    if must_conditions:
        return models.Filter(must=must_conditions)
    return None


def dense_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None, start_date=None, end_date=None):
    """Search using only dense (semantic) vectors."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss, start_date, end_date)
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


def sparse_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None, start_date=None, end_date=None):
    """Search using only sparse (BM25) vectors."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss, start_date, end_date)
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


def hybrid_search(client, query, limit=5, severity_filter=None, min_cvss=None, score_threshold=None, start_date=None, end_date=None):
    """Search using hybrid dense + sparse with RRF fusion."""
    query_filter = build_qdrant_filter(severity_filter, min_cvss, start_date, end_date)

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

