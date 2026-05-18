from gmail_service import get_gmail_service, fetch_unread_emails, get_email_details

service = get_gmail_service()

emails = fetch_unread_emails(service)

print(f"Found {len(emails)} unread emails")

for email in emails:
    subject, sender = get_email_details(service, email['id'])
    print("-----")
    print("From:", sender)
    print("Subject:", subject)