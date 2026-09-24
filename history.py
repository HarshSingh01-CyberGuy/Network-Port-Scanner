import os
import json

HISTORY_FILE = "scan_history.json"


def load_history():
    """
    Load previous scans from local JSON storage.
    """
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(
            HISTORY_FILE,
            "r"
        ) as file:
            return json.load(file)
    except Exception:
        return []


def save_history(history):
    """
    Save scan history to local JSON storage.
    """
    with open(
        HISTORY_FILE,
        "w"
    ) as file:
        json.dump(
            history,
            file,
            indent=4
        )