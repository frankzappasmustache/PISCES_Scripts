import requests
import datetime
import pandas as pd
import os

# === CONFIGURATION ===
# Kibana Settings
KIBANA_HOST = os.getenv("KIBANA_HOST", "")
KIBANA_USER = os.getenv("KIBANA_USER", "")
KIBANA_PASS = os.getenv("KIBANA_PASS", "")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "")   # your index or pattern

# Static blocklist URLs (other than api.blocklist.de)
STATIC_BLOCKLIST_URLS = [
    "https://cinsscore.com/list/ci-badguys.txt",               # CINSScore Badguys
    "https://www.spamhaus.org/drop/drop.txt",                  # Spamhaus DROP
    "https://www.spamhaus.org/blocklists/spamhaus-blocklist/",# Spamhaus SBL
    "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist",  # Feodo C2
    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",# Emerging Threats
    "https://check.torproject.org/exit-addresses",             # Tor Exit Nodes
    "http://feeds.dshield.org/block.txt",                      # DShield
    "https://malc0de.com/bl/IP_Blacklist.txt",                 # Malc0de
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"       # SSLBL
]

BATCH_SIZE = 500  # Number of IPs per query batch

# === FUNCTIONS ===
def fetch_ips(url):
    """Fetch a list of IPs from a URL, one per line."""
    resp = requests.get(url)
    resp.raise_for_status()
    return [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]


def chunk_list(lst, size):
    """Yield successive chunks of specified size."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def build_query(batch_ips, start_iso, end_iso):
    """Build ES DSL query using a terms filter on both fields."""
    return {
        "size": 10000,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                    {"bool": {
                        "should": [
                            {"terms": {"source.address.keyword": batch_ips}},
                            {"terms": {"destination.address.keyword": batch_ips}}
                        ],
                        "minimum_should_match": 1
                    }}
                ]
            }
        }
    }


def query_kibana(query_body):
    """Send a search request through Kibana's console proxy."""
    url = f"{KIBANA_HOST}/api/console/proxy?path={INDEX_PATTERN}/_search&method=POST"
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    resp = requests.post(url, json=query_body, headers=headers, auth=(KIBANA_USER, KIBANA_PASS))
    resp.raise_for_status()
    return resp.json().get("hits", {}).get("hits", [])

if __name__ == "__main__":
    # Compute dynamic time for api.blocklist.de (UTC now minus 2 hours)
    now = datetime.datetime.utcnow()
    two_hours_ago = now - datetime.timedelta(hours=2)
    time_param = two_hours_ago.strftime("%H:%M")
    blocklist_de_url = f"https://api.blocklist.de/getlast.php?time={time_param}"  # last two hours

    # Compile full list of blocklist URLs
    blocklist_urls = [blocklist_de_url] + STATIC_BLOCKLIST_URLS

    # Load blocklist IPs
    all_ips = []
    for url in blocklist_urls:
        try:
            ips = fetch_ips(url)
            all_ips.extend(ips)
            print(f"Loaded {len(ips)} IPs from {url}")
        except Exception as e:
            print(f"Error fetching {url}: {e}")
    all_ips = list(set(all_ips))
    print(f"Total unique IPs loaded: {len(all_ips)}")

    # Time window: last 7 days
    start_iso = (now - datetime.timedelta(days=7)).isoformat() + "Z"
    end_iso = now.isoformat() + "Z"
    print(f"Querying from {start_iso} to {end_iso}")

    # Batch queries to avoid oversized payloads
    all_hits = []
    for batch in chunk_list(all_ips, BATCH_SIZE):
        body = build_query(batch, start_iso, end_iso)
        hits = query_kibana(body)
        print(f"Batch of {len(batch)} IPs: {len(hits)} hits")
        all_hits.extend(hits)

    # Normalize and export
    rows = []
    for hit in all_hits:
        src = hit.get("_source", {}).get("source", {})
        dst = hit.get("_source", {}).get("destination", {})
        rows.append({
            "@timestamp": hit.get("_source", {}).get("@timestamp"),
            "source.address": src.get("address"),
            "destination.address": dst.get("address"),
            "index": hit.get("_index")
        })

    df = pd.DataFrame(rows)
    out_file = os.getenv("OUTPUT_FILE", "blocklist_hits.xlsx")
    df.to_excel(out_file, index=False)
    
    print(f"Results written to {out_file}")