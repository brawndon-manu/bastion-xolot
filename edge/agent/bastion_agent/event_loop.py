from __future__ import annotations

import time
import random
from datetime import datetime
from typing import Dict, Any
from bastion_agent.detection import handle_event
from bastion_agent.state import get_desired_state  # we read current state


TEST_MACS = [
    "aa:bb:cc:dd:ee:01",
    "aa:bb:cc:dd:ee:02",
    "aa:bb:cc:dd:ee:03"
]

SEVERITIES = ["low", "medium", "high"]


# ANSI Colors
RESET = "\033[0m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"


def generate_event() -> Dict[str, Any]:
    return {
        "mac": random.choice(TEST_MACS),
        "severity": random.choice(SEVERITIES),
        "reason": "simulated continuous activity"
    }


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


# CRITICAL: Prevent downgrade (HARD to SOFT)
def apply_severity_policy(event: Dict[str, Any]) -> Dict[str, Any]:
    mac = event.get("mac")
    severity = event.get("severity")

    state = get_desired_state()
    current = state.get("devices", {}).get(mac, {}).get("state")

    if current == "HARD" and severity == "medium":
        return {
            "result": {"status": "NOOP"},
            "transition": {"from": "HARD", "to": "HARD"}
        }

    return handle_event(event)


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


def main():
    print(f"{BOLD}{CYAN}Starting continuous detection loop...{RESET}\n")

    while True:
        event = generate_event()
        result = apply_severity_policy(event)  # use protected logic

        pretty_print(event, result)

        time.sleep(3)


if __name__ == "__main__":
    main()