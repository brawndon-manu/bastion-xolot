from __future__ import annotations

import time
import random
from datetime import datetime
from typing import Dict, Any
from bastion_agent.detection import handle_event


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
    else:
        return GREEN


def get_action_label(to_state: str | None) -> str:
    if to_state == "HARD":
        return f"{RED}HARD QUARANTINE{RESET}"
    elif to_state == "SOFT":
        return f"{YELLOW}SOFT QUARANTINE{RESET}"
    return f"{GREEN}NO ACTION{RESET}"


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
        print(f"Action: {get_action_label(to_state)}")

    print("=" * 60)


def main():
    print(f"{BOLD}{CYAN}Starting continuous detection loop...{RESET}\n")

    while True:
        event = generate_event()
        result = handle_event(event)

        pretty_print(event, result)

        time.sleep(3)


if __name__ == "__main__":
    main()