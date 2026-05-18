import pandas as pd

def detect_bruteforce(log_df):
    failed_attempts = log_df[log_df["status"] == "failed"]

    count = failed_attempts.groupby("ip").size()

    results = []

    for ip, attempts in count.items():
        if attempts > 8:
            risk = 90
            level = "High"
        elif attempts > 5:
            risk = 60
            level = "Medium"
        else:
            continue

        results.append({
            "ip": ip,
            "attempts": attempts,
            "risk_score": risk,
            "risk_level": level,
            "reason": f"{attempts} failed login attempts detected"
        })

    return results
