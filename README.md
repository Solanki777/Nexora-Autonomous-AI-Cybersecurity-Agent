# 🛡️ Nexora – Autonomous AI Cybersecurity Agent

## Overview

Nexora is an **Autonomous AI Cybersecurity Agent** designed to act as a virtual Security Operations Center (SOC). It continuously monitors system environments in real-time to detect and respond to cyber threats intelligently. 

By analyzing login logs, phishing emails, and suspicious URLs, Nexora classifies threats into low, medium, and high-risk levels. Instead of relying solely on manual intervention, the agent provides instant alerts and autonomous defensive actions, making your security system proactive rather than reactive.

## ✨ Key Features

- **Real-Time Log Monitoring**: Automatically reads system login logs (`login_logs.csv`) to detect repeated failed login attempts (Brute Force attacks).
- **Intelligent Phishing Detection**: Connects to your Gmail inbox via the Gmail API, scans unread emails, and uses AI-based keyword and structural analysis to flag phishing attempts.
- **URL Risk Analysis**: Manually input URLs into the dashboard to receive an instant risk score, threat classification, and agent decision.
- **Autonomous Response**:
    - Automatically blocks high-risk IP addresses and logs them.
    - Moves detected phishing emails directly to the Spam folder.
    - Creates a `Nexora_AI_Agent` label to organize scanned, safe emails.
    - Sends automated email alerts to administrators upon blocking an IP.
- **Interactive SOC Dashboard**: A comprehensive, real-time Streamlit dashboard displaying live threats, analytics, history, and system status with explainable AI outputs.

## 🛠️ Technology Stack

- **Dashboard / UI**: Streamlit
- **Data Processing**: Pandas
- **Backend / Logic**: Python
- **Integrations**: Google Workspace (Gmail API for email scanning)

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Solanki777/Nexora-Autonomous-AI-Cybersecurity-Agent.git
cd Nexora-Autonomous-AI-Cybersecurity-Agent
```

### 2. Install Dependencies
Ensure you have Python installed. Install the required libraries by running:
```bash
pip install streamlit pandas streamlit-autorefresh google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

### 3. Google API Configuration (For Gmail Scanner)
To enable the Gmail AI Scanner feature:
1. Go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a new project and enable the **Gmail API**.
3. Create **OAuth 2.0 Client ID** credentials and download the JSON file.
4. Rename the downloaded file to `credentials.json` and place it in the root directory of this project.
5. The first time you run the app and initiate a scan, a browser window will open asking you to authenticate. Once authenticated, a `token.json` file will be generated automatically.

### 4. Log Directory Setup
By default, Nexora looks for log files in a specific directory (typically used with local server setups like XAMPP). Ensure these files exist or update the paths in `app.py`:
- `C:\xampp\htdocs\security_logs\login_logs.csv`
- `C:\xampp\htdocs\security_logs\blocked_ips.txt`

*(Note: For standard local development, you can modify `app.py` lines 23, 91, and 119 to use relative paths like `./security_logs/...`)*

### 5. Run the Application
Start the Streamlit dashboard:
```bash
streamlit run app.py
```

## 📂 Project Structure

- `app.py`: The main Streamlit dashboard and application runner.
- `detection.py`: Logic for analyzing login logs and detecting brute force attacks based on failed attempts.
- `phishing_detector.py`: Implements feature extraction and risk scoring for URLs, email subjects, and content.
- `decision_engine.py`: Evaluates risk scores and determines the autonomous action (e.g., Immediate IP Block + Alert, Send Alert, Monitor).
- `gmail_service.py`: Handles Google OAuth authentication, fetching emails from Inbox and Spam, and moving malicious emails to the Spam folder using the Gmail API.
- `presentation.txt`: Original project documentation and overview.

## 🔮 Future Enhancements

- Integration of advanced Machine Learning models for higher accuracy in threat detection and behavior analysis.
- Network traffic monitoring, malware detection, and Intrusion Detection System (IDS) capabilities.
- Implementation of self-learning capabilities to adapt to new attack patterns over time.
- Cloud deployment, multi-user support, and real-time SIEM (Security Information and Event Management) integration.

## 👨‍💻 Author

**Mahesh Solanki**  
IT Student at Shantilal Shah Engineering College.
