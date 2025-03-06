
<h1 align="center">🚀 AI-Powered Phishing Detection System</h1>

An advanced <strong>Flask-based email phishing detection system</strong> that uses <strong>machine learning</strong> to analyze incoming emails in real-time.  
The system identifies <strong>phishing emails</strong>, provides <strong>instant notifications</strong>, and is seamlessly integrated with <strong>Gmail OAuth</strong> authentication.

📎 <strong>Live Demo:</strong> [ML-Based Phishing Detection](https://ml-based-phishing-detection.onrender.com)

---

## 📊 Features

- ✅ <strong>Gmail Integration (OAuth)</strong> – Securely fetch emails using <strong>Google OAuth</strong>.
- ✅ <strong>AI Phishing Detection</strong> – Classifies emails as <strong>Phishing</strong> or <strong>Safe</strong> using a <strong>Logistic Regression</strong> model.
- ✅ <strong>Real-Time Notifications</strong> – Receive <strong>instant alerts</strong> when a phishing email is detected.
- ✅ <strong>Email Analysis Dashboard</strong> – Displays complete email details (Sender, Subject, Date, Body).
- ✅ <strong>Automatic Data Management</strong> – Stores and auto-deletes email data in <strong>MongoDB</strong>.

---

## 📂 Project Structure

```
📦 phishing-detection-app/
├── 📁 static/                     # Static files (CSS, JS)
├── 📁 templates/                  # HTML templates
├── 📄 app.py                      # Main Flask app
├── 📄 email_fetch.py              # Fetch & analyze Gmail emails
├── 📄 phishing_model.py           # Machine learning model loader
├── 📄 requirements.txt            # Dependencies
├── 📄 config.py                   # Configuration settings
└── 📄 README.md                   # Project documentation
```

---

## 🛠️ Setup Instructions

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/your-username/phishing-detection-app.git
cd phishing-detection-app
```

### 2️⃣ Create a Virtual Environment

```bash
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
```

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Set Up Environment Variables

Create a `.env` file and add the following:

```bash
GMAIL_CLIENT_ID="your-google-client-id"
GMAIL_CLIENT_SECRET="your-google-client-secret"
MONGO_URI="your-mongodb-uri"
SECRET_KEY="your-secret-key"
```

### 5️⃣ Run the Application

```bash
python app.py
```

Access the app at: **http://localhost:5000**

---

## 🤖 Machine Learning Model

The app uses a **Logistic Regression** model trained on a phishing dataset:

- **Model Files**:  
    - `email_model.pkl`: Trained model for email classification  
    - `vectorizer.pkl`: **CountVectorizer** for text preprocessing  

### 🧠 How the Model Works:

1. **Preprocessing**: Converts email content into numerical form using `CountVectorizer`.  
2. **Prediction**: Classifies each email as either **Phishing** (1) or **Safe** (0).  
3. **Accuracy**: The model is trained for **high accuracy** on phishing datasets.  

---

## 📧 Real-Time Alerts

When a phishing email is detected:

- **Immediate notification** on the dashboard.
- Sends an **alert email** to the user.

---

## 📅 Scheduler (APScheduler)

Emails are fetched **every 60 seconds** using a background job:

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()
scheduler.add_job(fetch_emails, 'interval', seconds=60)
scheduler.start()
```

---

## 📈 Future Improvements

- 🔍 **Advanced NLP Models** (e.g., BERT for improved accuracy).  
- 📊 **Detailed Analytics** for email trends and threat reports.  
- 🔔 **User Configurations** for custom alert preferences.  

---

## 📜 License

This project is licensed under the **MIT License**. Feel free to use and enhance it!

---

## 🙌 Contributing

Contributions are welcome! To contribute:

1. **Fork** the repository.  
2. Create a new **branch**: `git checkout -b feature-branch`  
3. Submit a **Pull Request**.  

---

## 📞 Contact

For questions or feedback, contact:  
📧 **pandadharani9@gmail.com**  
🔗 **LinkedIn**: [Profile](https://www.linkedin.com/in/dharanidhar-panda-92491724b/)  

---
