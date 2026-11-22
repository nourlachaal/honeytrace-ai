"""Print the read-only API contract and the live dataset totals.

Used during the live demonstration: one command shows the health checks, the
thirteen approved event fields, the forbidden fields that never appear, and the
counts the dashboard aggregates from the full page set.

Example:
    python scripts/demo_security_proof.py
"""
import argparse
import json
import urllib.request
from collections import Counter

FORBIDDEN = ("raw_event", "metadata", "command", "message", "username")


def get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=10) as response:
        return json.loads(response.read())


def all_events(base: str, page_size: int = 200) -> list:
    """Follow next_cursor until the API stops returning one."""
    rows: list = []
    cursor = None
    while True:
        suffix = f"&cursor={cursor}" if cursor else ""
        page = get(base, f"/events?limit={page_size}{suffix}")
        rows.extend(page["items"])
        cursor = page.get("next_cursor")
        if not cursor:
            return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    base = args.api.rstrip("/")

    print(f"HoneyTrace AI - read-only API proof\nAPI: {base}\n")

    print("1. Health")
    for path in ("/health", "/health/db"):
        print(f"   {path:<12} {json.dumps(get(base, path))}")

    sample = get(base, "/events?limit=1")["items"][0]
    fields = list(sample.keys())
    leaked = sorted(set(fields) & set(FORBIDDEN))
    print(f"\n2. Event contract ({len(fields)} approved fields)")
    print("   " + ", ".join(fields))
    print(f"   forbidden fields present: {leaked or 'none'}")

    rows = all_events(base)
    sources = Counter(row["source"] for row in rows)
    sessions = {row["session_id"] for row in rows if row.get("session_id")}
    addresses = {row["src_ip"] for row in rows if row.get("src_ip")}
    types = Counter(row["event_type"] for row in rows if row.get("event_type"))
    print("\n3. Loaded dataset")
    ranked = sorted(sources.items(), key=lambda item: -item[1])
    print(f"   events {len(rows)}  " + "  ".join(f"{k} {v}" for k, v in ranked))
    print(f"   sessions {len(sessions)}, source IPs {len(addresses)}, event types {len(types)}")
    top, top_count = types.most_common(1)[0]
    print(f"   top event type {top} ({top_count})")

    incidents = get(base, "/incidents?limit=200")["items"]
    severity = Counter(item["severity"] for item in incidents)
    status = Counter(item["status"] for item in incidents)
    print("\n4. Incidents")
    print(f"   {len(incidents)} incidents, " + ", ".join(f"{k} {v}" for k, v in status.items()))
    print("   severity " + ", ".join(f"{k} {v}" for k, v in severity.items()))


if __name__ == "__main__":
    main()
