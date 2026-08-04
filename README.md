# Automated Endpoint Protection & Ransomware Mitigation Daemon

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux-orange)

A lightweight host-monitoring daemon engineered in Python to detect and mitigate rapid, unauthorized filesystem encryption (ransomware) in real time using **Shannon Entropy analysi**s over Linux process telemetry.

## 📌 Architecture & Threat Detection Logic
┌────────────────────────────────┐
│  Active Filesystem Telemetry   │
└───────────────┬────────────────┘
│
▼
┌────────────────────────────────┐
│  Linux procfs Event Ingestion  │
└───────────────┬────────────────┘
│
▼
┌────────────────────────────────┐
│   Shannon Entropy Calculation  │
└───────────────┬────────────────┘
│
[ > 7.5 Entropy? ]
/

YES                 NO
/

▼                       ▼
┌──────────────────┐  ┌───────────────────┐
│ Send OS SIGKILL  │  │ Continue Tracking │
└────────┬─────────┘  └───────────────────┘
│
▼
┌────────────────────────────────┐
│ Persistent MySQL Forensics Log │
└────────────────────────────────┘

1. **Host Ingestion:** Audits active file modification threads by continuously inspecting process execution states via the Linux `/proc` filesystem interface (`procfs`).
2. **Entropy Engine:** Computes mathematical Shannon Entropy ($H = -\sum p_i \log_2 p_i$) across sliding file-write byte streams to catch high-randomness signatures characteristic of symmetric encryption (e.g., AES, ChaCha20).
3. **Automated Mitigation:** Executes process termination logic via native OS signals (`SIGKILL`), stopping unauthorized process execution and neutralizing simulated ransomware threats in under **100ms**.
4. **Forensics Data Pipeline:** Records process execution paths, parent PIDs, user context, and mathematical entropy scores into a structured MySQL database for post-incident digital forensics analysis.

---

## 🛠️ Tech Stack & Key Tools
* **Language:** Python 3.10+
* **System Calls & OS:** Linux `procfs`, POSIX Signals (`SIGKILL`)
* **Data & Storage:** MySQL, SQL Pipelines
* **Algorithms:** Shannon Entropy Calculation, Thread Monitoring

---

## 🚀 Getting Started

### Prerequisites
* **OS:** Linux (Ubuntu 22.04+, Debian, Arch)
* **Python:** 3.10 or higher
* **Database:** MySQL Server 8.0+

### Installation & Execution

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/JanhN08/ransomware-mitigation-daemon.git](https://github.com/JanhN08/ransomware-mitigation-daemon.git)
   cd ransomware-mitigation-daemon
