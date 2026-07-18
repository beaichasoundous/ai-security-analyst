import json
import os
from datetime import datetime

THREATS_FILE = os.path.join(os.path.expanduser("~"), "threats.json")

def save_threat(log, analysis, severity):
    try:
        threat = {
            "timestamp": str(datetime.now()),
            "log": log,
            "analysis": analysis,
            "severity": severity
        }
        with open(THREATS_FILE, "a") as f:
            f.write(json.dumps(threat) + "\n")
        return True
    except Exception as e:
        print(f"Error saving threat: {e}")
        return False

def get_all_threats():
    threats = []
    try:
        if not os.path.exists(THREATS_FILE):
            return threats
        with open(THREATS_FILE, "r") as f:
            for line in f:
                if line.strip():
                    threats.append(json.loads(line))
    except Exception as e:
        print(f"Error loading threats: {e}")
    return threats