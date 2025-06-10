#!/usr/bin/env python3
import ipaddress
import json
from elasticsearch import Elasticsearch

# ── Configuration ───────────────────────────────────────────────────────────────
KIBANA_URL    = ''
KIBANA_USER   = ''
KIBANA_PASS   = ''
INDEX_PATTERN = ''
CLIENT_IDS    = []

# ── Helper (only keep public IPs) ───────────────────────────────────────────────
def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── Connect to Elasticsearch ────────────────────────────────────────────────────
# Build the Elasticsearch host URL from the Kibana URL
es_host = KIBANA_URL.replace('5601', '9200')  # e.g. "http://localhost:9200"
es = Elasticsearch(
    es_host,
    basic_auth=(KIBANA_USER, KIBANA_PASS)
)

# ── Fetch last‐hour docs for those clientIDs ────────────────────────────────────
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
        "source.address",
        "destination.address",
        "host.name",
        "clientID"
    ]
}

resp = es.search(index=INDEX_PATTERN, body=query)

# ── Build GeoJSON Features ─────────────────────────────────────────────────────
features = []
for hit in resp['hits']['hits']:
    src = hit['_source'].get('source', {})
    dst = hit['_source'].get('destination', {})
    hostnm = hit['_source'].get('host', {}).get('name', '')
    client = hit['_source'].get('clientID')

    # source point
    src_ip = src.get('address')
    lat = src.get('geo', {}).get('location', {}).get('lat')
    lon = src.get('geo', {}).get('location', {}).get('lon')
    if lat is not None and lon is not None and src_ip and is_public_ip(src_ip):
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lon, lat]
            },
            "properties": {
                "type": "source",
                "clientID": client,
                "ip": src_ip,
                "hostname": hostnm
            }
        })

    # destination point
    dst_ip = dst.get('address')
    lat = dst.get('geo', {}).get('location', {}).get('lat')
    lon = dst.get('geo', {}).get('location', {}).get('lon')
    if lat is not None and lon is not None and dst_ip and is_public_ip(dst_ip):
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lon, lat]
            },
            "properties": {
                "type": "destination",
                "clientID": client,
                "ip": dst_ip,
                "hostname": hostnm
            }
        })

# ── Write out FeatureCollection ────────────────────────────────────────────────
fc = {
    "type": "FeatureCollection",
    "features": features
}

output_path = "geo_hits.geojson"
with open(output_path, "w") as f:
    json.dump(fc, f, indent=2)

print(f"Wrote {len(features)} points to {output_path}. You can now upload this file to Kibana.")
