"""Anonymize Cowrie JSON Lines before sharing or committing them as a fixture.

- IP addresses -> 203.0.113.x (documentation range, one stable value per IP)
- session ids  -> short salted SHA-256 hash
- username / password / key / fingerprint fields removed
- message text of login and fingerprint events redacted (it contains credentials)

Always read the output before sharing it: command text (cowrie.command.input)
is kept on purpose and could contain secrets if you typed any.

Example:
    python scripts/anonymize_cowrie_sample.py ^
        --input data/raw/cowrie/cowrie-var/log/cowrie/cowrie.json ^
        --sessions 4288161e4a2f 2b26a4878af7 ^
        --output data/fixtures/cowrie/sample_anonymized.jsonl
"""
import argparse
import hashlib
import json
from pathlib import Path

DROP_KEYS = {"username", "password", "key", "fingerprint"}
REDACT_MESSAGE_PREFIXES = ("cowrie.login", "cowrie.client.fingerprint")


def anon_session(session: str, salt: str) -> str:
    return hashlib.sha256((salt + session).encode("utf-8")).hexdigest()[:12]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", nargs="*", default=None,
                        help="Real session ids to keep (default: all).")
    parser.add_argument("--salt", default="honeytrace")
    args = parser.parse_args()

    ip_map: dict[str, str] = {}
    session_map: dict[str, str] = {}
    kept = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.input.open(encoding="utf-8") as src, \
            args.output.open("w", encoding="utf-8") as out:
        for line in src:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            session = event.get("session")
            if args.sessions is not None and session not in args.sessions:
                continue

            for key in DROP_KEYS:
                event.pop(key, None)
            for ip_key in ("src_ip", "dst_ip"):
                if event.get(ip_key):
                    ip_map.setdefault(event[ip_key], f"203.0.113.{10 + len(ip_map)}")
                    event[ip_key] = ip_map[event[ip_key]]
            if session:
                session_map.setdefault(session, anon_session(session, args.salt))
                event["session"] = session_map[session]
            if event.get("sensor"):
                event["sensor"] = "honeypot-01"
            if str(event.get("eventid", "")).startswith(REDACT_MESSAGE_PREFIXES):
                event["message"] = "[REDACTED]"
            elif isinstance(event.get("message"), str):
                message = event["message"]
                for real_ip, fake_ip in ip_map.items():
                    message = message.replace(real_ip, fake_ip)
                for real_session, fake_session in session_map.items():
                    message = message.replace(real_session, fake_session)
                event["message"] = message

            out.write(json.dumps(event, ensure_ascii=False) + "\n")
            kept += 1

    print(f"Wrote {kept} events to {args.output}")
    for real, hashed in session_map.items():
        print(f"session {real} -> {hashed}")


if __name__ == "__main__":
    main()