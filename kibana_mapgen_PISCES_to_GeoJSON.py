#!/usr/bin/env python3
import ipaddress, json, sys, requests
from urllib.parse import quote

# ── CONFIG ─────────────────────────────────────────────────────────────────────
KIBANA_URL    = ''
KIBANA_USER   = ''
KIBANA_PASS   = ''
INDEX_PATTERN = ''
CLIENT_IDS    = []

# ── HELPERS ────────────────────────────────────────────────────────────────────
def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def kibana_search(index, query_body):
    path = f"/{index}/_search"
    url = (
        f"{KIBANA_URL}/api/console/proxy"
        f"?path={quote(path, safe='')}"
        f"&method=POST"
    )
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    r = requests.post(url, auth=(KIBANA_USER, KIBANA_PASS), headers=headers, json=query_body)
    if not r.ok:
        print(f"ERROR {r.status_code} calling {path!r}: {r.text}")
        sys.exit(1)
    return r.json()

# ── BUILD & RUN QUERY ───────────────────────────────────────────────────────────
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

resp = kibana_search(INDEX_PATTERN, query)
hits = resp.get("hits", {}).get("hits", [])
total = len(hits)
print(f"🔍 Query returned {total} hits.")

# ── DUMP FIRST 10 RAW HITS FOR INSPECTION ───────────────────────────────────────
print("\nFirst 10 raw hit _source fields:")
for hit in hits[:10]:
    print(json.dumps(hit["_source"], indent=2))
print("-" * 60)

# ── ATTEMPT GEOJSON CONVERSION WITH COUNTS ────────────────────────────────────
features = []
private_count = 0
missing_geo_count = 0

for hit in hits:
    src = hit["_source"].get("source", {})
    dst = hit["_source"].get("destination", {})
    hostnm = hit["_source"].get("host", {}).get("name", "")
    client = hit["_source"].get("clientID")

    for role, side in (("source", src), ("destination", dst)):
        ip  = side.get("address")
        loc = side.get("geo", {}).get("location", {})
        lat = loc.get("lat"); lon = loc.get("lon")

        if ip is None or lat is None or lon is None:
            missing_geo_count += 1
            continue

        if not is_public_ip(ip):
            private_count += 1
            continue

        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [lon, lat]},
            "properties": {
                "role":     role,
                "clientID": client,
                "ip":       ip,
                "hostname": hostnm
            }
        })

print(f"\nFiltered out {missing_geo_count} points missing geo fields.")
print(f"Filtered out {private_count} private-IP points.")
print(f"Will write {len(features)} features to geo_hits.geojson.")

# ── WRITE OUT IF ANY FEATURES ──────────────────────────────────────────────────
if features:
    fc = {"type": "FeatureCollection", "features": features}
    with open("geo_hits.geojson", "w") as f:
        json.dump(fc, f, indent=2)
    print("✅ geo_hits.geojson written successfully.")
else:
    print("⚠️ No features to write. Check the counts above for why.")
