### 🔐 AI N.A.S – The Cyber-Aware AI Assistant

**AI N.A.S (Nabeel’s AI Assistant)** is an intelligent, voice- and text-based assistant built in Python that combines AI interaction with basic cybersecurity capabilities. It leverages the **Google Gemini API** for general AI functionalities while integrating essential system security features, making it a dual-purpose assistant for both productivity and protection.

---

### 🚀 Key Features

* **AI-Powered Conversations**
  Supports both **text** and **voice** input/output, offering natural human-like interaction for queries, tasks, and general assistance.

* **Cybersecurity Toolkit (Built-in)**
  Includes fundamental security modules:

  * 🔍 **Port Scanner** – Scans open ports on a given host.
  * 🧠 **Threat Detector** – Performs basic threat analysis before startup.
  * 🔥 **Firewall Manager** – Helps simulate basic firewall creation and rule handling.

* **Startup Routine**
  When launched, `main.py`:

  1. Runs a threat detection scan.
  2. If safe, displays available commands.
  3. Lets the user choose between text or voice interaction.

* **Command Handling**
  Responds to both general queries (e.g., greetings, questions) and cybersecurity-specific commands like:

  * `scan ports`
  * `detect threats`
  * `manage firewall`
  * `exit assistant`

---

### 🛠️ Tech Stack

* **Python 3.x**
* **Google Gemini API** (for AI responses)
* `speech_recognition`, `pyttsx3` for voice I/O
* Custom modules:

  * `firewall_manager.py`
  * `thread_detector.py`
  * `port_scanner.py`

---

### 📦 Folder Structure

```
AI-NAS/
├── main.py                # Entry point
├── firewall_manager.py    # Firewall functionalities
├── thread_detector.py     # Threat detection logic
├── port_scanner.py        # Port scanning module
└── requirements.txt       # Dependencies (optional)
```

---

### 🎯 Purpose

AI N.A.S is developed as a **mini-project** to demonstrate the combination of **AI capabilities** with **basic cybersecurity utilities** — ideal for learners and hobbyists interested in building dual-purpose assistants.
