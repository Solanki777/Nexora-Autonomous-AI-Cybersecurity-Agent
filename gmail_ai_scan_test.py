from gmail_service import (
    get_gmail_service,
    fetch_unread_emails,
    get_email_details,
    move_to_spam,
    get_or_create_label
)

from phishing_detector import predict_phishing

service = get_gmail_service()

# Get or create Nexora label
nexora_label_id = get_or_create_label(service)

emails = fetch_unread_emails(service)

print(f"Scanning {len(emails)} unread Inbox emails...\n")

# Trusted senders (whitelist)
TRUSTED_SENDERS = [
    "linkedin.com",
    "google.com",
    "github.com",
    "solankimaheshkhash7@gmail.com"
]

for email in emails:
    msg_id = email['id']
    subject, sender = get_email_details(service, msg_id)

    print("-----")
    print("From:", sender)
    print("Subject:", subject)

    sender_lower = sender.lower()

    # Skip trusted emails
    if any(trusted in sender_lower for trusted in TRUSTED_SENDERS):
        print("Risk Score: 0")
        print("Risk Level: Safe (Trusted Sender)")
        
        # Mark as read + add Nexora label
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={
                'removeLabelIds': ['UNREAD'],
                'addLabelIds': [nexora_label_id]
            }
        ).execute()

        print("✔ Marked as Read + Labeled (Trusted)\n")
        continue

    # Run AI phishing detection
    score, level = predict_phishing(subject)

    print("Risk Score:", score)
    print("Risk Level:", level)

    if level == "High":
        # Move suspicious mail to spam
        move_to_spam(service, msg_id)
        print("⚠ Moved to Spam\n")
    else:
        # Mark safe emails as read and label them
        service.users().messages().modify(
            userId='me',
            id=msg_id,
            body={
                'removeLabelIds': ['UNREAD'],
                'addLabelIds': [nexora_label_id]
            }
        ).execute()
        print("✔ Marked as Read + Labeled (Safe)\n")