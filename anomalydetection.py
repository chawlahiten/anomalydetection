import re
from datetime import datetime
from collections import defaultdict, Counter

# ---------- CONFIG ----------
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
INTERVAL_THRESHOLD = 0.9   # 90% same interval = suspicious
FREQUENCY_THRESHOLD = 10   # more than 10 API calls
REPEAT_THRESHOLD = 5       # same endpoint repeated >5 times

# ---------- PARSE LOG ----------
def parse_log(file_path):
    user_data = defaultdict(list)

    with open(file_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        if "authorizedUserId" in line:
            # Extract timestamp
            time_match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", line)
            # Extract endpoint
            endpoint_match = re.search(r'GET\s+"([^"]+)"', line)
            # Extract user ID
            user_match = re.search(r'authorizedUserId:\s*"([^"]+)"', line)

            if time_match and endpoint_match and user_match:
                timestamp = datetime.strptime(time_match.group(), "%Y-%m-%dT%H:%M:%S")
                endpoint = endpoint_match.group(1)
                user = user_match.group(1)

                user_data[user].append((timestamp, endpoint))

    return user_data


# ---------- DETECT CONSTANT INTERVAL ----------
def detect_constant_intervals(timestamps):
    if len(timestamps) < 3:
        return False

    intervals = []
    timestamps = sorted(timestamps)

    for i in range(1, len(timestamps)):
        diff = (timestamps[i] - timestamps[i-1]).total_seconds()
        intervals.append(diff)

    # Count most common interval
    counter = Counter(intervals)
    most_common_count = counter.most_common(1)[0][1]

    ratio = most_common_count / len(intervals)

    return ratio >= INTERVAL_THRESHOLD


# ---------- ANALYZE ----------
def analyze(user_data):
    suspicious_users = []

    for user, records in user_data.items():
        timestamps = [r[0] for r in records]
        endpoints = [r[1] for r in records]

        # 1. Constant interval check
        is_bot = detect_constant_intervals(timestamps)

        # 2. High frequency
        high_freq = len(records) > FREQUENCY_THRESHOLD

        # 3. Repeated endpoints
        endpoint_counts = Counter(endpoints)
        repeated = any(count > REPEAT_THRESHOLD for count in endpoint_counts.values())

        # Combine signals
        if is_bot or (high_freq and repeated):
            suspicious_users.append({
                "user": user,
                "is_bot_pattern": is_bot,
                "total_requests": len(records),
                "repeated_endpoints": repeated
            })

    return suspicious_users


# ---------- MAIN ----------
if __name__ == "__main__":
    file_path = "web_activity.log"  # change if needed

    data = parse_log(file_path)
    results = analyze(data)

    print("\n🚨 Suspicious Users:\n")
    for r in results:
        print(f"User: {r['user']}")
        print(f"  Total Requests: {r['total_requests']}")
        print(f"  Bot Pattern Detected: {r['is_bot_pattern']}")
        print(f"  Repeated Endpoints: {r['repeated_endpoints']}")
        print("-" * 40)