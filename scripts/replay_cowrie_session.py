"""Replay a scripted, harmless session against the LOCAL Cowrie honeypot.

Lab use only: refuses any host other than 127.0.0.1.
Needs: pip install paramiko

Examples:
    python scripts/replay_cowrie_session.py --scenario normal
    python scripts/replay_cowrie_session.py --scenario attack
"""
import argparse
import time
from datetime import datetime, timezone

import paramiko

# Commands stay local to the fake shell. Do NOT add wget/curl: Cowrie may
# really download the URL from the Internet.
SCENARIOS = {
    "normal": ["whoami", "pwd", "ls", "exit"],
    "attack": [
        "cat /etc/passwd",
        "uname -a",
        "ps",
        "cd /tmp",
        "ls -la",
        "chmod +x /tmp/test.sh",
        "exit",
    ],
}


def run(scenario: str, port: int, user: str, password: str, delay: float) -> None:
    started = datetime.now(timezone.utc)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=port,
        username=user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=10,
    )
    channel = client.invoke_shell()
    time.sleep(delay)
    for command in SCENARIOS[scenario]:
        channel.send(command + "\n")
        time.sleep(delay)
        if channel.recv_ready():
            channel.recv(65535)  # discard output
    channel.close()
    client.close()
    ended = datetime.now(timezone.utc)
    print(f"scenario={scenario} started={started.isoformat()} ended={ended.isoformat()}")
    print("Note these times: use them to find the session_id and set its label.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", default="azerty")
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()
    run(args.scenario, args.port, args.user, args.password, args.delay)


if __name__ == "__main__":
    main()