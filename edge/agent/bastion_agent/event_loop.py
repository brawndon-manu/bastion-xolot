from __future__ import annotations

import time
import random
import json
from datetime import datetime
from typing import Dict, Any
from collections import defaultdict
from bastion_agent.detection import handle_event
from bastion_agent.suricata_adapter import parse_eve_log


TEST_MACS = [
    "aa:bb:cc:dd:ee:01",
    "aa:bb:cc:dd:ee:02",
    "aa:bb:cc:dd:ee:03"
]

SEVERITIES = ["low", "medium", "high"]

STATE_FILE = "/var/lib/bastion/enforcement/desired_state.json"


# ANSI Colors
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"


# Dashboard counters
event_count = 0
status_counts = defaultdict(int)
mac_counter = defaultdict(int)


def generate_event() -> Dict[str, Any]:
    return {
        "mac": random.choice(TEST_MACS),
        "severity": random.choice(SEVERITIES),
        "reason": "simulated continuous activity"
    }


def read_current_state(mac: str) -> str | None:
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        return data.get("devices", {}).get(mac, {}).get("state")
    except Exception:
        return None


def get_color(severity: str) -> str:
    if severity == "HIGH":
        return RED
    elif severity == "MEDIUM":
        return YELLOW
    return GREEN


def get_action_label(to_state: str | None, status: str) -> str:
    if status == "NOOP":
        return f"{GREEN}ALREADY ENFORCED{RESET}"

    if to_state == "HARD":
        return f"{RED}HARD QUARANTINE{RESET}"
    elif to_state == "SOFT":
        return f"{YELLOW}SOFT QUARANTINE{RESET}"

    return f"{GREEN}NO ACTION{RESET}"


# Prevent downgrade (HARD to SOFT)
def apply_severity_policy(event: Dict[str, Any]) -> Dict[str, Any]:
    mac = event.get("mac")
    severity = event.get("severity")

    current = read_current_state(mac)

    if current == "HARD" and severity == "medium":
        return {
            "result": {"status": "NOOP"},
            "transition": {"from": "HARD", "to": "HARD"}
        }

    return handle_event(event)

def resolve_mac(ip: str) -> str | None:
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]  # skip header

        for line in lines:
            parts = line.split()
            ip_addr = parts[0]
            mac_addr = parts[3]

            if ip_addr == ip and mac_addr != "00:00:00:00:00:00":
                return mac_addr.lower()

    except Exception:
        pass

    return None


def pretty_print(event: Dict[str, Any], result: Dict[str, Any]) -> None:
    mac = event.get("mac")
    severity = event.get("severity", "").upper()
    reason = event.get("reason")

    result_block = result.get("result", {})
    status = result_block.get("status")

    transition = result.get("transition", {})
    from_state = transition.get("from")
    to_state = transition.get("to")

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    color = get_color(severity)

    print("\n" + "=" * 60)
    print(f"{BOLD}{CYAN}[{timestamp}]{RESET}")

    print(f"\n{BOLD}[EVENT]{RESET}")
    print(f"MAC: {mac}")
    print(f"Severity: {color}{severity}{RESET}")
    print(f"Reason: {reason}")

    print(f"\n{BOLD}[RESULT]{RESET}")
    print(f"Status: {status}")

    if from_state and to_state:
        print(f"Transition: {from_state} → {to_state}")
        print(f"Current State: {to_state}")
        print(f"Action: {get_action_label(to_state, status)}")

    print("=" * 60)


def print_dashboard():
    print("\n" + "#" * 60)
    print(f"{BOLD}{CYAN}LIVE SYSTEM SUMMARY{RESET}")

    print(f"Total Events: {event_count}")
    print(f"EXECUTED: {status_counts['EXECUTED']}")
    print(f"NOOP: {status_counts['NOOP']}")
    print(f"IGNORED: {status_counts['IGNORED']}")

    # Count current state
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        devices = data.get("devices", {})
        hard = sum(1 for d in devices.values() if d.get("state") == "HARD")
        soft = sum(1 for d in devices.values() if d.get("state") == "SOFT")
    except Exception:
        hard = soft = 0

    print(f"HARD Devices: {hard}")
    print(f"SOFT Devices: {soft}")

    # Top offender
    if mac_counter:
        top_mac = max(mac_counter, key=mac_counter.get)
        print(f"Top Offender: {top_mac} ({mac_counter[top_mac]} events)")

    print("#" * 60 + "\n")

def stream_eve_log(log_path: str):
    with open(log_path, "r") as f:
        f.seek(0, 2)  # move to end of file

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            try:
                data = json.loads(line)

                # Only process alerts (real threats)
                if data.get("event_type") != "alert":
                    continue

                alert = data.get("alert", {})
                sev = alert.get("severity", 3)

                # Map Suricata severity → our system
                if sev == 1:
                    severity = "high"
                elif sev == 2:
                    severity = "medium"
                else:
                    severity = "low"
                yield {
                    "mac": "aa:bb:cc:dd:ee:21",  # placeholder mapping
                    "severity": severity,
                    "reason": alert.get("signature", "unknown alert")
                }

            except Exception:
                continue

def main():
    global event_count

    print(f"{BOLD}{CYAN}Starting continuous detection loop...{RESET}\n")

    seen_events = set()

    for event in stream_eve_log("/var/log/suricata/eve.json"):
        event_id = (event["mac"], event["reason"])
    
        if event_id in seen_events:
            continue

        seen_events.add(event_id)

        mac = event["mac"]

        result = apply_severity_policy(event)

        status = result.get("result", {}).get("status", "UNKNOWN")

        # Update counters
        event_count += 1
        status_counts[status] += 1
        mac_counter[mac] += 1

        pretty_print(event, result)

        # Print dashboard every 10 events
        if event_count % 10 == 0:
            print_dashboard()


if __name__ == "__main__":
    main()
    