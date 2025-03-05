import os
import pickle
import base64
from dotenv import load_dotenv
from pymongo import MongoClient
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from dateutil import parser
from datetime import datetime

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

load_dotenv()

# 🔹 Connect to MongoDB
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["email_db"]
emails_collection = db["emails"]

# Path to the mounted credential.json
CREDENTIALS_PATH = '/etc/secrets/CREDENTIALS_JSON'
TOKEN_PATH = '/etc/secrets/token.pickle'

def get_gmail_service():
    """Authenticate using OAuth and return Gmail API service."""
    creds = None

    # Load existing token if available
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, 'rb') as token:
            creds = pickle.load(token)

    # If credentials are invalid, refresh or initiate OAuth flow
    if not creds or not creds.valid:
        try:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                # Load credentials from Render-mounted file
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
                creds = flow.run_local_server(port=5003, access_type='offline', prompt='consent')

            # Save new credentials for reuse
            with open(TOKEN_PATH, 'wb') as token:
                pickle.dump(creds, token)

        except Exception as e:
            print(f"❌ OAuth Error: {e}")
            return None

    return build('gmail', 'v1', credentials=creds)

def extract_body(parts):
    """Extract the email body."""
    for part in parts:
        if part['mimeType'] == 'text/plain':
            body = part['body'].get('data', '')
            return base64.urlsafe_b64decode(body).decode('utf-8', errors='ignore')
        elif 'parts' in part:
            return extract_body(part['parts'])
    return "No body found"

def fetch_and_store_emails():
    """Fetch and store emails from Gmail to MongoDB."""
    service = get_gmail_service()
    if not service:
        print("❌ Failed to authenticate Gmail service.")
        return []

    results = service.users().messages().list(userId='me', labelIds=['INBOX']).execute()
    messages = results.get('messages', [])

    new_emails = []

    for message in messages:
        msg_id = message['id']

        # 🔹 Skip if already exists
        if emails_collection.find_one({"message_id": msg_id}):
            continue

        msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        headers = msg['payload']['headers']

        from_email = next((item['value'] for item in headers if item['name'] == 'From'), 'Unknown Sender')
        subject = next((item['value'] for item in headers if item['name'] == 'Subject'), 'No Subject')
        date_str = next((item['value'] for item in headers if item['name'] == 'Date'), 'Unknown Date')

        try:
            date = parser.parse(date_str)
        except Exception as e:
            print(f"❌ Failed to parse date: {e}")
            date = datetime.utcnow()

        body = extract_body(msg['payload']['parts']) if 'parts' in msg['payload'] else "No body found"

        email_entry = {
            'message_id': msg_id,
            'from': from_email,
            'subject': subject,
            'date': date,
            'body': body,
            'status': "Pending"
        }

        emails_collection.insert_one(email_entry)
        new_emails.append(email_entry)
        print(f"✅ New Email Saved: {subject}")

    if not new_emails:
        print("✅ No new emails found.")

    return new_emails

if __name__ == "__main__":
    print("📩 Fetching new emails and storing in MongoDB...")
    new_emails = fetch_and_store_emails()
    print(f"✅ Fetched {len(new_emails)} new emails.")

    # Example: Display emails sorted by date DESCENDING
    print("\n📬 Displaying Emails (Newest First):")
    latest_emails = emails_collection.find().sort("date", -1)
    for email in latest_emails:
        print(f"{email['date']} - {email['subject']} - {email['from']}")
