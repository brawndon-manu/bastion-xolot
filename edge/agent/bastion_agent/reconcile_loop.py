import time
import traceback

from bastion_agent.reconcile import reconcile_once

INTERVAL = 10  # seconds


def main():
    while True:
        try:
            tx = reconcile_once()
            print(tx["result"])
        except Exception as e:
            print("reconcile error:", e)
            traceback.print_exc()

        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()