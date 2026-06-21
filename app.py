
import os
import datetime
import streamlit as st
import pandas as pd
from streamlit_autorefresh import st_autorefresh

# Gmail Integration
from gmail_service import (
    get_gmail_service,
    fetch_unread_emails,
    get_email_details,
    move_to_spam,
    get_or_create_label
)

from detection import detect_bruteforce
from decision_engine import agent_decision
from phishing_detector import predict_phishing
st_autorefresh(interval=5000, key="datarefresh")


# Configure file paths, preferring the local project directory if present
base_dir = os.path.dirname(os.path.abspath(__file__))
local_log_file = os.path.join(base_dir, "security_logs", "login_logs.csv")
local_blocked_file = os.path.join(base_dir, "security_logs", "blocked_ips.txt")

log_file = local_log_file if os.path.exists(local_log_file) else r"C:\xampp\htdocs\security_logs\login_logs.csv"
blocked_file = local_blocked_file if os.path.exists(local_blocked_file) else r"C:\xampp\htdocs\security_logs\blocked_ips.txt"

if os.path.exists(blocked_file):
    with open(blocked_file, "r") as f:
        saved_ips = [line.strip() for line in f.readlines()]
else:
    saved_ips = []



def send_alert_email(ip):
    import smtplib
    from email.mime.text import MIMEText

    sender = "solankimaheshkhash7@gmail.com"
    password = "cickfhnatkpbvcsu"
    receiver = "solankimaheshkhash230@gmail.com"

    subject = "Nexora Security Notification"

    body = f"""
Nexora Security Notification

A high-risk login event was detected.

Blocked IP: {ip}

The IP has been blocked automatically by Nexora.

Regards,
Nexora Security Agent
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()

        st.success(f"✅ Alert email sent for {ip}")

    except Exception as e:
        st.error(f"❌ Email Error: {e}")
        print("EMAIL ERROR:", e)



# Initialize session state
if "threat_history" not in st.session_state:
    st.session_state.threat_history = []

if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = saved_ips

# 📧 Email threat storage
if "email_threats" not in st.session_state:
    st.session_state.email_threats = []


if "system_under_threat" not in st.session_state:
    st.session_state.system_under_threat = False

st.set_page_config(page_title="Nexora AI Agent", layout="wide")

st.title("🛡️ Nexora – Autonomous Cyber Defense Agent")
st.markdown("Real-time AI Threat Monitoring System")

st.divider()

# ================= LIVE LOGIN LOG READING =================


if os.path.exists(log_file):
    df = pd.read_csv(log_file, names=["ip", "status", "timestamp"])
    st.write("### 📂 Live Login Logs")
    st.dataframe(df)
    # ================= DETECTION ENGINE =================
    st.session_state.system_under_threat = False
    results = detect_bruteforce(df)

    if results:
        st.session_state.system_under_threat = True
        st.write("## 🚨 Threats Detected")

        for r in results:

            # Skip already blocked IPs
            if r["ip"] in st.session_state.blocked_ips:
                continue

            r["timestamp"] = datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # High-risk threat → block once
            if r["risk_level"] == "High":

                if r["ip"] not in st.session_state.blocked_ips:

                    st.session_state.blocked_ips.append(r["ip"])

                    with open(blocked_file, "a") as f:
                        f.write(r["ip"] + "\n")

                    send_alert_email(r["ip"]) 

            # Save incident once
            st.session_state.threat_history.append(r)

            st.error(f"IP: {r['ip']}")
            st.write(f"Attempts: {r['attempts']}")
            st.write(f"Risk Score: {r['risk_score']}")
            st.write(f"Risk Level: {r['risk_level']}")
            st.write("---")
            

else:
    st.warning("No login logs found yet.")
    st.stop()



reset_system = st.button("🔄 Reset System")

if reset_system:
    st.session_state.threat_history = []
    st.session_state.system_under_threat = False
    st.session_state.blocked_ips = []

    with open(blocked_file, "w") as f:
        f.write("")

    with open(log_file, "w") as f:
        f.write("")

    st.success("System fully reset.")



col_a, col_b, col_c, col_d = st.columns(4)

total_events = len(st.session_state.threat_history)

high_risk_count = sum(
    1 for threat in st.session_state.threat_history
    if threat.get("risk_level") == "High"
)

medium_risk_count = sum(
    1 for threat in st.session_state.threat_history
    if threat.get("risk_level") == "Medium"
)

low_risk_count = sum(
    1 for threat in st.session_state.threat_history
    if threat.get("risk_level") == "No"
)

with col_a:
    st.metric("📊 Total Events", total_events)

with col_b:
    st.metric("🔴 High Risk", high_risk_count)

with col_c:
    st.metric("🟡 Medium Risk", medium_risk_count)

with col_d:
    st.metric("🟢 No Risk", low_risk_count)

st.divider()


# ================= TWO COLUMN LAYOUT =================
st.divider()
col1, col2 = st.columns(2)


with col2:
    st.header("🌐 Phishing URL Detection")

    url_input = st.text_input("Enter a URL to analyze")

    if url_input:
        score, level = predict_phishing(url_input)
        if level == "High":
            st.session_state.system_under_threat = True


        st.write(f"Phishing Risk Score: {score}")
        # Clamp score to 0–100 for safe progress bar
        safe_score = min(score, 100)
        st.progress(safe_score / 100)
        st.write(f"Risk Level: {level}")

        decision = agent_decision(score)

        st.write("### 🧠 Agent Decision")
        st.info(f"Action: {decision['action']}")
        st.success(decision["message"])

# ================= THREAT HISTORY =================
st.divider()
st.header("📜 Threat History")

if st.session_state.threat_history:
    st.dataframe(pd.DataFrame(st.session_state.threat_history))
else:
    st.write("No historical threats recorded yet.")

st.divider()
st.header("🚫 Blocked IP Addresses")

if st.session_state.blocked_ips:
    for ip in st.session_state.blocked_ips:
        st.error(f"Blocked IP: {ip}")
else:
    st.write("No IPs blocked.")



# ================= THREAT ANALYTICS =================
if st.session_state.threat_history:
    st.divider()
    st.header("📊 Threat Analytics Overview")

    df_history = pd.DataFrame(st.session_state.threat_history)

    # Risk distribution chart
    risk_distribution = df_history["risk_level"].value_counts()

    st.subheader("Threat Distribution by Risk Level")
    st.bar_chart(risk_distribution)

    # Timeline trend if timestamp exists
    if "timestamp" in df_history.columns:
        st.subheader("Threat Timeline")

        df_history["timestamp"] = pd.to_datetime(df_history["timestamp"])
        timeline = df_history.groupby(
            df_history["timestamp"].dt.strftime("%H:%M:%S")
        ).size()

        st.line_chart(timeline)

# ================= SYSTEM STATUS =================
st.divider()
st.subheader("🔐 System Status")

if st.session_state.system_under_threat:
    st.error("🚨 System Status: UNDER THREAT")
else:
    st.success("✅ System Status: SECURE")


st.divider()

# ================= GMAIL AI EMAIL SCANNER =================
st.divider()
st.header("📧 Nexora Gmail Threat Scanner")

st.markdown("Scan your Inbox for phishing and suspicious emails using AI.")

scan_mail = st.button("📨 Start Email Scan")

if scan_mail:
    try:
        service = get_gmail_service()
        nexora_label_id = get_or_create_label(service)

        emails = fetch_unread_emails(service)

        st.info(f"Scanning {len(emails)} emails from Inbox + Spam folders...")

        TRUSTED_SENDERS = [
            "linkedin.com",
            "google.com",
            "github.com",
            "solankimaheshkhash7@gmail.com"
        ]

        detected_emails = []

        for email in emails:

            msg_id = email['id']

            # 🔥 FIRST get subject and sender (FIXED ORDER)
            subject, sender = get_email_details(service, msg_id)
            sender_lower = sender.lower()

            # THEN detect folder (Inbox / Spam)
            full_msg = service.users().messages().get(
                userId='me',
                id=msg_id
            ).execute()

            labels = full_msg.get('labelIds', [])

            if 'SPAM' in labels:
                source_folder = "Spam"
            elif 'INBOX' in labels:
                source_folder = "Inbox"
            else:
                source_folder = "Other"

            
            # Skip trusted emails
            if any(trusted in sender_lower for trusted in TRUSTED_SENDERS):
                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={
                        'removeLabelIds': ['UNREAD'],
                        'addLabelIds': [nexora_label_id]
                    }
                ).execute()
                continue

            score, level = predict_phishing(subject)

            email_data = {
                "Sender Email (Attacker)": sender,
                "Source Folder": source_folder,
                "Subject": subject,
                "Risk Score": score,
                "Risk Level": level
            }

            detected_emails.append(email_data)

            if level == "High":
                move_to_spam(service, msg_id)

                # 🚨 Show real phishing attacker alert
                st.error(f"🚨 High-Risk Phishing Sender: {sender} (Folder: {source_folder})")

                # Log attacker email ONCE with timestamp (SOC style)
                os.makedirs("security_logs", exist_ok=True)
                with open("security_logs/malicious_senders.txt", "a") as f:
                    f.write(f"{datetime.datetime.now()} | {sender} | {subject}\n")
            else:
                # Mark as read + label safe emails
                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={
                        'removeLabelIds': ['UNREAD'],
                        'addLabelIds': [nexora_label_id]
                    }
                ).execute()

        st.session_state.email_threats = detected_emails

    except Exception as e:
        st.error(f"Gmail Scan Error: {str(e)}")


# 📊 Display Email Threat Table
if st.session_state.email_threats:
    st.subheader("🚨 Detected Suspicious Emails")
    df_emails = pd.DataFrame(st.session_state.email_threats)
    st.dataframe(df_emails)

    high_risk = [e for e in st.session_state.email_threats if e["Risk Level"] == "High"]

    st.metric("🔴 High Risk Emails", len(high_risk))
else:
    st.write("No suspicious emails detected yet.")
st.caption("Nexora AI Agent | Autonomous Cyber Defense System | Developed by Mahesh Solanki")


