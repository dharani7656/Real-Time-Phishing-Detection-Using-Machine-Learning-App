
🚀 AI-Powered Phishing Detection System
An advanced Flask-based email phishing detection system that uses machine learning to analyze incoming emails in real-time. The system identifies phishing emails, provides instant notifications, and is seamlessly integrated with Gmail OAuth authentication.

🔗 Live Demo: ML-Based Phishing Detection

📊 Features
✅ Gmail Integration (OAuth) – Securely fetch emails using Google OAuth.
✅ AI Phishing Detection – Classifies emails as Phishing or Safe using a Logistic Regression model.
✅ Real-Time Notifications – Receive instant alerts when a phishing email is detected.
✅ Email Analysis Dashboard – Displays complete email details (Sender, Subject, Date, Body).
✅ Automatic Data Management – Stores and auto-deletes email data in MongoDB.
✅ Background Scheduler – Fetches and analyzes emails every 60 seconds using APScheduler.
✅ User Authentication – Supports both Google Login (via Firebase) and traditional login.
🛠️ Tech Stack
Backend: Flask, Flask-SocketIO, APScheduler
Machine Learning: Scikit-learn (Logistic Regression)
Database: MongoDB
Frontend: HTML, CSS, JavaScript
Authentication: OAuth (Gmail), Firebase (Google Login)
Deployment: Render
📂 Project Structure
php
Copy
Edit
📦 phishing-detection-app/
├── 📁 static/                     # Static files (CSS, JS)
├── 📁 templates/                  # HTML templates
├── 📄 app.py                      # Main Flask app
├── 📄 email_fetch.py              # Fetch & analyze Gmail emails
├── 📄 phishing_model.py           # Machine learning model loader
├── 📄 requirements.txt            # Dependencies
├── 📄 config.py                   # Configuration settings
└── 📄 README.md                   # Project documentation
📊 Phishing Detection Workflow
User Authentication: Users log in via Gmail OAuth or Firebase Google Login.
Email Fetching: System retrieves emails using the Gmail API every 60 seconds.
Phishing Analysis: Each email is processed through the Logistic Regression model.
Real-Time Updates: Flask-SocketIO displays live analysis results on the dashboard.
Email Alerts: Phishing emails trigger instant email notifications for user awareness.
Database Management: Email records are stored and automatically deleted after a set time.
📌 Setup Instructions
1️⃣ Clone the Repository
bash
Copy
Edit
git clone https://github.com/your-username/phishing-detection-app.git
cd phishing-detection-app
2️⃣ Create a Virtual Environment
bash
Copy
Edit
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
3️⃣ Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
4️⃣ Set Up Environment Variables
Create a .env file and add the following:

bash
Copy
Edit
GMAIL_CLIENT_ID="your-google-client-id"
GMAIL_CLIENT_SECRET="your-google-client-secret"
MONGO_URI="your-mongodb-uri"
SECRET_KEY="your-secret-key"
5️⃣ Run the Application
bash
Copy
Edit
python app.py
Access the app at: http://localhost:5000

🤖 Machine Learning Model
The app uses a Logistic Regression model trained on a phishing dataset:

Model Files:
email_model.pkl: Trained model for email classification
vectorizer.pkl: CountVectorizer for text preprocessing
🧠 How the Model Works:
Preprocessing: Converts email content into numerical form using CountVectorizer.
Prediction: Classifies each email as either Phishing (1) or Safe (0).
Accuracy: The model is trained for high accuracy on phishing datasets.
📊 Example Dashboard

📧 Real-Time Alerts
When a phishing email is detected:

Immediate notification on the dashboard.
Sends an alert email to the user.
📅 Scheduler (APScheduler)
Emails are fetched every 60 seconds using a background job:

python
Copy
Edit
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_emails, 'interval', seconds=60)
scheduler.start()
📈 Future Improvements
🔍 Advanced NLP Models (e.g., BERT for improved accuracy).
📊 Detailed Analytics for email trends and threat reports.
🔔 User Configurations for custom alert preferences.
📜 License
This project is licensed under the MIT License. Feel free to use and enhance it!

🙌 Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a new branch: git checkout -b feature-branch
Submit a Pull Request.
📞 Contact
For questions or feedback, contact:
📧 pandadharani9@gmail.com
🔗 LinkedIn: https://www.linkedin.com/in/dharanidhar-panda-92491724b/

