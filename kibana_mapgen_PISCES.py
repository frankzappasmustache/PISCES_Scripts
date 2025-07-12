#!/usr/bin/env python3
import time
import pandas as pd
import matplotlib.pyplot as plt
from elasticsearch import Elasticsearch

# ── Configuration (from your VT script) ────────────────────────────────────────
KIBANA_URL    = ''
KIBANA_USER   = ''
KIBANA_PASS   = ''
INDEX_PATTERN = ''
CLIENT_IDS    = []

# ── Connect to Elasticsearch (via Kibana host) ─────────────────────────────────
es = Elasticsearch(
    [KIBANA_URL.replace('5601', '9200')],
    http_auth=(KIBANA_USER, KIBANA_PASS),
    scheme="http"
)

# ── Query last 1h for those clientIDs ───────────────────────────────────────────
query = {
    "size": 10000,
    "query": {
        "bool": {
            "must": [
                {"terms": {"clientID.keyword": CLIENT_IDS}},
                {"range": {"@timestamp": {"gte": "now-1h"}}}
            ]
        }
    },
    "_source": [
        "source.geo.location.lat",
        "source.geo.location.lon",
        "destination.geo.location.lat",
        "destination.geo.location.lon",
        "clientID"
    ]
}

resp = es.search(index=INDEX_PATTERN, body=query)

# ── Build DataFrame ─────────────────────────────────────────────────────────────
records = []
for hit in resp['hits']['hits']:
    src = hit['_source'].get('source', {}).get('geo', {}).get('location', {})
    dst = hit['_source'].get('destination', {}).get('geo', {}).get('location', {})
    client = hit['_source'].get('clientID')
    if src.get('lat') is not None and src.get('lon') is not None:
        records.append({
            "lat": src['lat'],
            "lon": src['lon'],
            "type": "source",
            "clientID": client
        })
    if dst.get('lat') is not None and dst.get('lon') is not None:
        records.append({
            "lat": dst['lat'],
            "lon": dst['lon'],
            "type": "destination",
            "clientID": client
        })

df = pd.DataFrame(records)
if df.empty:
    print("No geo-hits in the last hour for clients:", CLIENT_IDS)
    exit(0)

# ── Plot with Matplotlib ────────────────────────────────────────────────────────
plt.figure(figsize=(10, 6))

# plot source in blue circles, destination in red squares
for kind, marker, label in [
    ("source", "o", "Source"),
    ("destination", "s", "Destination")
]:
    subset = df[df["type"] == kind]
    plt.scatter(
        subset["lon"], subset["lat"],
        s=50, marker=marker, alpha=0.7, label=label, edgecolors='k'
    )

plt.title("Geo-Locations for Hits in Last Hour")
plt.xlabel("Longitude")
plt.ylabel("Latitude")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
