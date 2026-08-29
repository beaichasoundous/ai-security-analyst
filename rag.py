import chromadb
from chromadb.utils import embedding_functions

# use chromadb's built-in embedding function
embedding_fn = embedding_functions.DefaultEmbeddingFunction()

# create client
client = chromadb.PersistentClient(path="./chroma_db")

# create collection with embedding function
collection = client.get_or_create_collection(
    name="threats",
    embedding_function=embedding_fn
)


def add_threat(threat_text, threat_id=None):
    if threat_id is None:
        threat_id = [f"doc_{i}" for i in range(len(threat_text))]

    
    collection.add(
        documents=threat_text,
        ids=threat_id
    )
    print(f"Added {len(threat_text)} documents")

def search_threats(query, n_results=3):
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )
    return results

sample_threats = [
    "SSH brute force: multiple failed password attempts from same IP on port 22",
    "SQL injection attempt: UNION SELECT detected in HTTP request",
    "Port scan detected: firewall blocked connections to ports 21, 22, 80, 443",
    "DDoS pattern: thousands of HTTP requests from single IP in 1 minute",
]

add_threat(sample_threats)
# test search
results = search_threats("failed SSH login attempts")
print(results)