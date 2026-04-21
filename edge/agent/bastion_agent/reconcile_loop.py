import time
import traceback

from bastion_agent.reconcile import reconcile_once
from bastion_agent.storage import init_local_db

INTERVAL = 10  # seconds


def main():
    init_local_db()

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