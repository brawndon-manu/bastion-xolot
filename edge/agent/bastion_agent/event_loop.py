from __future__ import annotations

import time
import random
from bastion_agent.detection import handle_event


TEST_MACS = [
    "aa:bb:cc:dd:ee:01",
    "aa:bb:cc:dd:ee:02",
    "aa:bb:cc:dd:ee:03"
]

SEVERITIES = ["low", "medium", "high"]


def generate_event():
    return {
        "mac": random.choice(TEST_MACS),
        "severity": random.choice(SEVERITIES),
        "reason": "simulated continuous activity"
    }


def main():
    print("Starting continuous detection loop...\n")

    while True:
        event = generate_event()
        result = handle_event(event)

        print("EVENT:", event)
        print("RESULT:", result)
        print("-" * 50)

        time.sleep(3)


if __name__ == "__main__":
    main()