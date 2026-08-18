import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY: str = os.environ.get("GROQ_API_KEY", "your-api-key-here")
GROQ_MODEL: str = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

COLLECTION_NAME: str = "cve-intel"
DENSE_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
SPARSE_MODEL: str = "Qdrant/bm25"

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_CACHE_FILE: str = "cve_cache.json"
CACHE_EXPIRY_HOURS: int = 24
QDRANT_PATH: str = os.environ.get("QDRANT_PATH", "./qdrant_db")



