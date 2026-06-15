from qdrant_client import QdrantClient, models
from config import COLLECTION_NAME, DENSE_MODEL, SPARSE_MODEL


def create_collection(client):
    """Create a Qdrant collection with both dense and sparse vectors."""
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

def dense_search(client, query, limit=5):
    """Search using only dense (semantic) vectors."""
    response = client.query_points(
        collection_name=COLLECTION_NAME,
        query=models.Document(text=query, model=DENSE_MODEL),
        using="dense",
        limit=limit,
        with_payload=True,
    )
    return response.points

def sparse_search(client, query, limit=5):
    """Search using only sparse (BM25) vectors."""
    response = client.query_points(
        collection_name=COLLECTION_NAME,
        query=models.Document(text=query, model=SPARSE_MODEL),
        using="sparse",
        limit=limit,
        with_payload=True,
    )
    return response.points

def hybrid_search(client, query, limit=5, severity_filter=None):
    """Search using hybrid dense + sparse with RRF fusion."""
    query_filter = None
    if severity_filter:
        query_filter = models.Filter(
            must=[
                models.FieldCondition(
                    key="severity",
                    match=models.MatchValue(value=severity_filter),
                )
            ]
        )

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
    return response.points
