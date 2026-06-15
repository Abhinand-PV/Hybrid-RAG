import os

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "your-api-key-here")
GROQ_MODEL = "llama-3.3-70b-versatile"

COLLECTION_NAME = "cve-intel"
DENSE_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
SPARSE_MODEL = "Qdrant/bm25"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
