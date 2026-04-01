from __future__ import annotations

import time
import random
from typing import Dict, Any
from bastion_agent.detection import handle_event


TEST_MACS = [
    "aa:bb:cc:dd:ee:01",
    "aa:bb:cc:dd:ee:02",
    "aa:bb:cc:dd:ee:03"
]

SEVERITIES = ["low", "medium", "high"]


def generate_event() -> Dict[str, Any]:
    return {
        "mac": random.choice(TEST_MACS),
        "severity": random.choice(SEVERITIES),
        "reason": "simulated continuous activity"
    }


def pretty_print(event: Dict[str, Any], result: Dict[str, Any]) -> None:
    mac = event.get("mac")
    severity = event.get("severity", "").upper()
    reason = event.get("reason")

    result_block = result.get("result", {})
    status = result_block.get("status")

    transition = result.get("transition", {})
    from_state = transition.get("from")
    to_state = transition.get("to")

    print("\n[EVENT]")
    print(f"MAC: {mac}")
    print(f"Severity: {severity}")
    print(f"Reason: {reason}")

    print("\n[RESULT]")
    print(f"Status: {status}")

    if from_state and to_state:
        print(f"Transition: {from_state} → {to_state}")

    print("-" * 50)


def main():
    print("Starting continuous detection loop...\n")

    while True:
        event = generate_event()
        result = handle_event(event)

        pretty_print(event, result)

        time.sleep(3)


if __name__ == "__main__":
    main()