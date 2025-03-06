# app.py
import eventlet
eventlet.monkey_patch()
from functools import wraps
import traceback
from scapy.all import rdpcap
import os
import uuid
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from pymongo import MongoClient
from dotenv import load_dotenv
import requests
from werkzeug.utils import secure_filename
from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, jsonify, redirect, flash, session, url_for
from flask_socketio import SocketIO
from pymongo import MongoClient
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
import requests
from email_alert import send_phishing_alert_email
import pickle
from app_gmail_api import fetch_and_store_emails, get_gmail_service
from werkzeug.utils import secure_filename
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, login_required
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify, session, current_app
from werkzeug.utils import secure_filename
import logging
from google_auth_oauthlib.flow import Flow


# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
ALLOWED_EXTENSIONS = {'pcap'}

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CREDENTIALS_PATH = '/etc/secrets/CREDENTIALS_JSON'




# Initialize MongoDB
client = MongoClient(os.getenv("MONGO_URI"))
db = client["email_db"]
emails_collection = db["emails"]
admins_collection = db["admins"]
users_collection = db["users"]
pcap_collection = db["pcap_files"]

UPLOAD_FOLDER = 'uploads/pcap_files'
REPORT_FOLDER = 'uploads/reports'
ALLOWED_EXTENSIONS = {'pcap'}

REPORT_FOLDER = 'uploads/reports'
PCAP_FOLDER = 'uploads/pcap_files'

app.config['PCAP_FOLDER'] = PCAP_FOLDER
app.config['REPORT_FOLDER'] = REPORT_FOLDER

# Create directories if not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)    
os.makedirs(PCAP_FOLDER, exist_ok=True)  




# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
client = WebApplicationClient(GOOGLE_CLIENT_ID)



socketio = SocketIO(app, async_mode='eventlet')



# 🔹 Load ML Model & Vectorizer
model = pickle.load(open("models/email_model.pkl", "rb"))
vectorizer = pickle.load(open("models/vectorizer.pkl", "rb"))
# Helper function to check allowed file extensions
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Load the phishing detection model and vectorizer once
with open('models/email_model.pkl', 'rb') as model_file:
    phishing_model = pickle.load(model_file)

with open('models/vectorizer.pkl', 'rb') as vectorizer_file:
    vectorizer = pickle.load(vectorizer_file)


def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function



# Function to analyze PCAP files
def analyze_pcap(filepath):
    try:
        packets = rdpcap(filepath)
        num_packets = len(packets)
        protocols = set(str(packet.proto) for packet in packets if hasattr(packet, 'proto'))  # Ensure protocols are strings
        return {
            'filename': os.path.basename(filepath),
            'num_packets': num_packets,
            'protocols': list(protocols)
        }
    except Exception as e:
        current_app.logger.error(f"PCAP analysis failed: {e}")
        return {
            'filename': os.path.basename(filepath),
            'num_packets': 0,
            'protocols': []
        }
    
def analyze_email_content(email_text):
    """Analyze email content using the phishing detection model."""
    try:
        email_vector = vectorizer.transform([email_text])
        prediction = phishing_model.predict(email_vector)[0]
        return "phishing" if prediction == 1 else "safe"
    except Exception as e:
        logging.error(f"Error analyzing email: {e}")
        return "error"

def send_email(recipient_email, pdf_path):
    sender_email = os.getenv("SENDER_EMAIL")
    app_password = os.getenv("APP_PASSWORD")# Use the generated app password from Google
    subject = 'Security Analysis Report - [Phishing Incident Response]'

    email_template = f"""
    <html>
    <head></head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <p>Dear Valued User,</p>

        <p>We have completed the analysis of your submitted network traffic data. Attached to this email is the detailed Security Analysis Report summarizing our findings.</p>

        <p><strong>Key Highlights:</strong></p>
        <ul>
            <li>Identified potential phishing and malicious traffic patterns.</li>
            <li>Packet-level inspection conducted to detect anomalies.</li>
            <li>Recommendations provided for improving your network security posture.</li>
        </ul>

        <p>We encourage you to review the attached report carefully and implement the suggested security measures to safeguard your systems.</p>

        <p>If you have any questions or need further assistance, feel free to contact our security team.</p>

        <p>Best regards,<br>
        <strong>Cybersecurity Analysis Team</strong><br>
        [Your Company Name]</p>
    </body>
    </html>
    """

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(email_template, 'html'))

    with open(pdf_path, 'rb') as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(pdf_path)}')
        msg.attach(part)

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, app_password)
    text = msg.as_string()
    server.sendmail(sender_email, recipient_email, text)
    server.quit()

def background_email_fetch():
    """Background job to fetch new emails and analyze for phishing."""
    try:
        # Fetch and store new emails
        new_emails = fetch_and_store_emails()

        if new_emails:
            with app.app_context():
                for email in new_emails:
                    email_text = f"{email.get('subject', '')} {email.get('body', '')}"
                    result = analyze_email_content(email_text)

                    # Update email status in MongoDB
                    emails_collection.update_one(
                        {"message_id": email['message_id']},
                        {"$set": {"status": result}}
                    )

                    # Add phishing status for frontend display
                    email['phishing_status'] = "Phishing Email" if result == "phishing" else "Safe Email"

                    # Emit new email event to the frontend
                    try:
                        socketio.emit("new_email", email)
                        logging.info(f"New email emitted: {email['message_id']}")
                    except Exception as emit_error:
                        logging.error(f"Socket.IO emit failed: {emit_error}")

                    # Send phishing alert if needed
                    if result == "phishing":
                        email_record = emails_collection.find_one({"message_id": email['message_id']})
                        user_email = email_record.get('user_email') if email_record else None

                        if user_email:
                            email_subject = email.get('subject', 'No Subject')
                            email_from = email.get('from', 'Unknown Sender')
                            logging.info(f"Sending phishing alert to: {user_email}")
                            send_phishing_alert_email(user_email, email_subject, email_from)
                        else:
                            logging.warning("User email not found for phishing alert.")

        logging.info("✅ Email fetch and analysis complete.")
    except Exception as e:
        logging.error(f"❌ Error in background job: {e}\n{traceback.format_exc()}")



def get_gmail_service():
    creds = None

    # Check if credentials already exist
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    # Refresh if credentials are expired
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return None

    # If valid, return the service
    if creds and creds.valid:
        return build('gmail', 'v1', credentials=creds)

    return None




@app.route('/')
def index():
    user = None
    if 'user' in session:
        user = users_collection.find_one({'email': session['user']})
    return render_template('anothercombined.html', user=user)




# Signup route
@app.route('/signup', methods=['POST'])
def signup():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    if users_collection.find_one({'email': email}):
        return 'User already exists! Try logging in.'

    # Hash password before storing
    hashed_password = generate_password_hash(password)

    # Create new user
    users_collection.insert_one({
        'name': name,
        'email': email,
        'password': hashed_password
    })

    return 'Signup successful! You can now log in.'

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_collection.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            session['user'] = email
            return redirect(url_for('index'))

        return 'Invalid credentials!'

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route("/postphishing")
# @user_login_required
def postphishing():
    return render_template("PostPhishing.html")

# PCAP Upload Route with Debug Logging and Analysis
@app.route('/upload-pcap', methods=['POST'])
def upload_pcap():
    # Ensure user is authenticated
    if 'user' not in session:
        current_app.logger.error("PCAP Upload Failed: User not authenticated")
        return jsonify({'error': 'User not authenticated'}), 401

    # Validate uploaded file
    if 'pcap' not in request.files:
        current_app.logger.error("PCAP Upload Failed: No file uploaded")
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['pcap']

    if file.filename == '':
        current_app.logger.error("PCAP Upload Failed: No file selected")
        return jsonify({'error': 'No file selected'}), 400

    # Check for valid file extension
    if not allowed_file(file.filename, {'pcap'}):
        current_app.logger.error("PCAP Upload Failed: Invalid file format")
        return jsonify({'error': 'Invalid file format'}), 400

    try:
        user_email = session['user']

        # Ensure the PCAP upload folder exists
        upload_folder = app.config.get('PCAP_FOLDER', 'uploads/pcaps')
        os.makedirs(upload_folder, exist_ok=True)

        # Create a unique filename to avoid conflicts
        original_filename = secure_filename(file.filename)
        unique_id = uuid.uuid4().hex
        unique_filename = f"{unique_id}_{original_filename}"
        file_path = os.path.join(upload_folder, unique_filename)

        # Save the uploaded file
        file.save(file_path)

        # Analyze the uploaded PCAP file
        analysis_result = analyze_pcap(file_path)

        # Ensure analysis returns expected fields
        num_packets = analysis_result.get('num_packets', 0)
        protocols = analysis_result.get('protocols', [])

        # Log successful upload
        current_app.logger.info(f"PCAP Uploaded: {file_path} by {user_email}")

        # Store upload details in MongoDB
        pcap_collection.insert_one({
            'user_email': user_email,
            'original_filename': original_filename,
            'unique_filename': unique_filename,
            'file_path': file_path,
            'num_packets': num_packets,
            'protocols': protocols
        })

        return jsonify({
            'message': 'PCAP uploaded successfully',
            'filename': original_filename,
            'email': user_email,
            'num_packets': num_packets,
            'protocols': protocols
        }), 200

    except Exception as e:
        current_app.logger.error(f"PCAP Upload Error: {e}")
        return jsonify({'error': 'Internal Server Error'}), 500



@app.route('/landing')
def landing_page():
    """Display the landing page."""
    return render_template('landing_page.html')

@app.route('/check-auth')
def check_auth():
    """
    Check if the user is authenticated.
    If authenticated, redirect to the dashboard.
    If not, initiate the Google authentication flow.
    """
    # Ensure Gmail API credentials are available
    service = get_gmail_service()

    # If credentials are valid, authenticate the session
    if service:
        session["authenticated"] = True
        return redirect(url_for('dashboard'))

    # If not authenticated, start Google OAuth flow
    session["authenticated"] = False
    flow = Flow.from_client_secrets_file(
        '/etc/secrets/CREDENTIALS_JSON',
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    return redirect(auth_url)



@app.route('/authenticate')
def authenticate():
    """
    Step 1: Initiate Google OAuth Flow.
    """
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_PATH,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent'
    )

    # Store state to validate later
    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """
    Handle Google OAuth callback and store credentials.
    """
    flow = Flow.from_client_secrets_file(
        '/etc/secrets/CREDENTIALS_JSON',
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )

    # Exchange the authorization code for credentials
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials

    # Save credentials to token.pickle for reuse
    with open('token.pickle', 'wb') as token:
        pickle.dump(creds, token)

    session["authenticated"] = True
    return redirect(url_for('dashboard'))



@app.route('/dashboard')
def dashboard():
    """
    Show the dashboard if authenticated.
    """
    # Ensure the user is authenticated via OAuth
    if not session.get("authenticated"):
        return redirect(url_for("authenticate"))

    # Ensure Gmail API service is available
    service = get_gmail_service()
    if not service:
        return redirect(url_for("authenticate"))

    # Fetch emails from MongoDB collection (show newest first)
    emails = list(emails_collection.find().sort("date", -1))

    # Render the dashboard with emails
    return render_template('dashboard.html', emails=emails)


@app.route("/fetch-emails", methods=["GET"])
def fetch_emails():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized. Please authenticate first."}), 401

    emails = list(emails_collection.find({}, {"_id": 0}).sort("date", -1))
    return jsonify(emails)



@app.route("/analyze-email", methods=["POST"])
def analyze_email():
    # Ensure the user is logged in
    if 'user' not in session:
        return jsonify({"error": "Unauthorized access"}), 401
    
    # Get the logged-in user's email from the session
    user_email = session['user']

    data = request.json
    email_id = data.get("message_id")
    email_text = data.get("text", "")
    email_subject = data.get("subject", "No Subject")
    email_from = data.get("from", "Unknown")

    if not email_text:
        return jsonify({"error": "No email content provided"}), 400

    # Analyze the email for phishing
    email_vector = vectorizer.transform([email_text])
    prediction = model.predict(email_vector)[0]
    prediction_result = "phishing" if prediction == 1 else "safe"

    # Update email status in the database
    if email_id:
        emails_collection.update_one(
            {"message_id": email_id},
            {"$set": {"status": prediction_result}}
        )

    # If phishing → Send email notification + Real-time socket alert
    if prediction_result == "phishing":
        # 📧 Send Email Notification to the logged-in user
        send_phishing_alert_email(user_email, email_subject, email_from)

        # ⚠️ Emit Real-time Frontend Notification via Socket.IO
        socketio.emit("phishing_alert", {
            "from": email_from,
            "subject": email_subject,
            "user_email": user_email
        })

    return jsonify({"message_id": email_id, "prediction": prediction_result})




@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = admins_collection.find_one({'username': username, 'password': password})

        if admin:
            session['admin_logged_in'] = True
            flash('Login Successful!', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid Username or Password', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
# @admin_login_required
def admin():
    # Fetch PCAP details from MongoDB
    pcap_details = list(db.pcap_files.find({}, {'_id': 0, 'original_filename': 1, 'user_email': 1, 'num_packets': 1, 'protocols': 1, 'unique_filename' : 1}))

    # Ensure protocols are formatted correctly (optional validation)
    for detail in pcap_details:
        detail['protocols'] = detail.get('protocols', [])

    return render_template('admin_dashboard.html', pcap_details=pcap_details)

# Logout Route
@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('admin_login'))


@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['PCAP_FOLDER'], filename), as_attachment=True)


@app.route('/upload_email_report', methods=['POST'])
def upload_email_report():
    if 'pdf_file' not in request.files or 'email' not in request.form:
        return 'Missing file or email'

    pdf_file = request.files['pdf_file']
    recipient_email = request.form['email']

    if pdf_file.filename == '':
        return 'No selected file'

    filename = secure_filename(pdf_file.filename)
    pdf_path = os.path.join(app.config['REPORT_FOLDER'], filename)
    pdf_file.save(pdf_path)

    send_email(recipient_email, pdf_path)
    return 'Email sent successfully'    
@app.route('/get_phishing_stats')
def get_phishing_stats():
    safe_count = emails_collection.count_documents({'status': 'Safe Email'})
    phishing_count = emails_collection.count_documents({'status': 'Phishing Email'})

    return jsonify({'safe_count': safe_count, 'phishing_count': phishing_count})


@socketio.on('request_stats')
def handle_request_stats():
    try:
        safe_count = emails_collection.count_documents({'status': 'Safe Email'})
        phishing_count = emails_collection.count_documents({'status': 'Phishing Email'})

        socketio.emit('update_stats', {
            'safe_count': safe_count,
            'phishing_count': phishing_count
        })
    except Exception as e:
        socketio.emit('update_stats_error', {'error': str(e)})

# 🔹 Start Background Job for Automatic Email Fetching Every 60 Seconds
    # Initialize and start the scheduler
    scheduler = BackgroundScheduler()

    if not scheduler.running:
        scheduler.add_job(background_email_fetch, "interval", seconds=60)
        scheduler.start()
        logging.info("Phishing detection system started.")        



if __name__ == '__main__':
    

    print("🚀 Flask App is running with Real-time Email Fetching and Socket.IO")

    # Ensure Flask binds to the correct port on Render
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 10000)), debug=False)
