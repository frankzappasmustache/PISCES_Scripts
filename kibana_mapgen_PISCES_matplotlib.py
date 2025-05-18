#!/usr/bin/env python3

import ipaddress
import json
import sys
import requests
import pandas as pd
import matplotlib.pyplot as plt
import mplcursors
from urllib.parse import quote

# ── CONFIGURATION ─────────────────────────────────────────────────────────────
KIBANA_URL    = ''
KIBANA_USER   = ''
KIBANA_PASS   = ''
INDEX_PATTERN = ''
CLIENT_IDS    = []
# ── HELPER: only keep public IPs ────────────────────────────────────────────────
def is_public_ip(ip):
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── HELPER: issue ES query via Kibana Console Proxy ────────────────────────────
def kibana_search(index, query_body):
    path = f"/{index}/_search"
    url = (
        f"{KIBANA_URL}/api/console/proxy"
        f"?path={quote(path, safe='')}"
        f"&method=POST"
    )
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    r = requests.post(
        url, auth=(KIBANA_USER, KIBANA_PASS), headers=headers, json=query_body
    )
    if not r.ok:
        print(f"ERROR {r.status_code} calling {path!r}: {r.text}")
        sys.exit(1)
    return r.json()

# ── BUILD & EXECUTE QUERY ──────────────────────────────────────────────────────
query = {
    "size": 10000,
    "query": {
        "bool": {
            "must": [
                {"terms": {"clientID.keyword": CLIENT_IDS}},
                {"range": {"@timestamp": {"gte": "now-1h"}}},
                {"exists": {"field": "source.geo.location.lat"}}
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

# ── ASSEMBLE RECORDS ───────────────────────────────────────────────────────────
records = []
for hit in hits:
    src = hit["_source"].get("source", {})
    dst = hit["_source"].get("destination", {})
    hostnm = hit["_source"].get("host", {}).get("name", "")
    client = hit["_source"].get("clientID")
    for role, side in (("source", src), ("destination", dst)):
        ip = side.get("address")
        loc = side.get("geo", {}).get("location", {})
        lat = loc.get("lat")
        lon = loc.get("lon")
        if ip and lat is not None and lon is not None and is_public_ip(ip):
            records.append({
                "latitude": lat,
                "longitude": lon,
                "role": role,
                "clientID": client,
                "ip": ip,
                "hostname": hostnm
            })

if not records:
    print("No public geo-hits found for the given criteria.")
    sys.exit(0)

df = pd.DataFrame(records)
import ace_tools as tools; tools.display_dataframe_to_user(name="Geo Hits Last Hour", dataframe=df)

# ── PLOT WITH MATPLOTLIB ───────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10, 6))
colors = {"source": "blue", "destination": "red"}
markers = {"source": "o", "destination": "s"}

for role in df["role"].unique():
    subset = df[df["role"] == role]
    ax.scatter(
        subset["longitude"],
        subset["latitude"],
        label=role.title(),
        c=colors[role],
        marker=markers[role],
        edgecolors='k',
        s=50,
        alpha=0.7
    )

cursor = mplcursors.cursor(ax.collections, hover=True)
@cursor.connect("add")
def on_add(sel):
    i = sel.index
    row = df.iloc[i]
    sel.annotation.set_text(
        f"{row['role'].title()} ({row['clientID']})\n"
        f"IP: {row['ip']}\n"
        f"Host: {row['hostname']}"
    )

ax.set_title("Public Source & Destination Geo-Locations (Last Hour)")
ax.set_xlabel("Longitude")
ax.set_ylabel("Latitude")
ax.legend()
ax.grid(True)
plt.tight_layout()
plt.show()
