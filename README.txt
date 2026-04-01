Log Anomaly Detector (Cybersecurity Project)
Overview

This project analyzes web request logs to detect suspicious user behavior such as:

* Automated API calls (bot activity)
* Repeated endpoint access
* High-frequency requests

It simulates a real-world SOC (Security Operations Center) use case.


  Features

* Detects constant interval requests (bot detection)
* Identifies repeated API endpoint usage
* Flags high-frequency access patterns
* Extracts and analyzes user activity from logs


 Tech Stack

* Python
* Regex
* Collections (Counter, defaultdict)
* Datetime



How to Run

```bash
anomalydetection.py
```

---

 Input Format

* Log file: `web_activity.log`
* Contains grouped requests by IP
* Each request includes timestamp, endpoint, and user ID

---

 Detection Logic

* Constant time intervals → automation
* Repeated endpoints → scraping behavior
* High request volume → anomaly

---

 Example Output

``
 Suspicious Users:

User: mdB7yD2dp1BFZPontHBQ1Z
  Total Requests: 25
  Bot Pattern Detected: True
  Repeated Endpoints: True
```

---

Future Improvements

* Visualization dashboard
* Machine Learning anomaly detection
* Real-time log monitoring

---

 👨‍💻 Author

Hiten Chawla
