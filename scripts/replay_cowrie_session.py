"""Replay a scripted, harmless session against the LOCAL Cowrie honeypot.

Lab use only: refuses any host other than 127.0.0.1.
Needs: pip install paramiko

Every run is appended to data/manifests/replay_manifest.csv with its time
window and status, so sessions can be labeled afterwards without guessing.

Examples:
    python scripts/replay_cowrie_session.py --scenario normal-basic --test-run-id RUN-2026-11-16-002
    python scripts/replay_cowrie_session.py --scenario attack-basic --test-run-id RUN-2026-11-16-002
"""
import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path

import paramiko

MANIFEST = Path("data/manifests/replay_manifest.csv")
MANIFEST_FIELDS = ["test_run_id", "scenario_id", "label", "started_utc", "ended_utc", "status"]

# label 0 = normal, 1 = attack-like. Commands stay inside Cowrie's fake shell.
# Do NOT add wget/curl: Cowrie may really download the URL from the Internet.
SCENARIOS = {
    "normal-basic": (0, ["whoami", "pwd", "ls", "exit"]),
    "normal-admin": (0, ["date", "uptime", "ls -la", "pwd", "exit"]),
    "attack-basic": (1, [
        "cat /etc/passwd", "uname -a", "ps", "cd /tmp",
        "ls -la", "chmod +x /tmp/test.sh", "exit",
    ]),
    "attack-recon": (1, [
        "whoami", "id", "uname -a", "cat /etc/shadow",
        "cat /etc/passwd", "exit",
    ]),
}


def append_manifest(row: dict) -> None:
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    new_file = not MANIFEST.exists()
    with MANIFEST.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=MANIFEST_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)


def run(scenario: str, test_run_id: str, port: int, user: str,
        password: str, delay: float) -> None:
    label, commands = SCENARIOS[scenario]
    started = datetime.now(timezone.utc)
    status = "interrupted"  # becomes "completed" only if everything ran
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1", port=port, username=user, password=password,
            look_for_keys=False, allow_agent=False, timeout=10,
        )
        channel = client.invoke_shell()
        time.sleep(delay)
        for command in commands:
            channel.send(command + "\n")
            time.sleep(delay)
            if channel.recv_ready():
                channel.recv(65535)  # discard output
        channel.close()
        status = "completed"
    finally:
        client.close()
        ended = datetime.now(timezone.utc)
        append_manifest({
            "test_run_id": test_run_id, "scenario_id": scenario, "label": label,
            "started_utc": started.isoformat(), "ended_utc": ended.isoformat(),
            "status": status,
        })
        print(f"{scenario} {status} {started.isoformat()} -> {ended.isoformat()}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--test-run-id", required=True)
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="azerty")
    parser.add_argument("--delay", type=float, default=2.0)
    args = parser.parse_args()
    run(args.scenario, args.test_run_id, args.port, args.user, args.password, args.delay)


if __name__ == "__main__":
    main()