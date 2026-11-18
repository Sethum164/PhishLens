# PhishLens – Phishing Email Detection and Investigation Platform

PhishLens is a web-based phishing email detection and investigation platform developed using Python and Flask. It helps security analysts examine suspicious email messages, identify potential indicators of compromise (IOCs), assess security risks, and manage investigations through a SOC-style dashboard.

## Project Overview

Phishing is a common cybersecurity threat in which attackers use deceptive emails to steal sensitive information, distribute malware, or gain unauthorized access.

PhishLens provides a centralized platform to analyze `.eml` email files and organize the investigation process.

## Key Features

- **Email Analysis:** Upload and analyze `.eml` email files.
- **Email Header Analysis:** Examine sender information, Reply-To mismatches, Return-Path, and SPF, DKIM, and DMARC results.
- **IOC Extraction:** Extract URLs, domains, and IP addresses from email content.
- **URL Threat Analysis:** Identify potentially suspicious URL characteristics.
- **Domain Analysis:** Examine suspicious domain characteristics.
- **DNS Analysis:** Retrieve DNS information for extracted domains.
- **Attachment Analysis:** Identify suspicious attachment extensions and MIME-type mismatches.
- **Risk Scoring:** Calculate a risk score and classify investigations as Low, Medium, High, or Critical.
- **Threat Intelligence:** Perform local heuristic checks and optional external threat intelligence lookups.
- **Investigation Management:** Maintain investigation records, update statuses, and add analyst notes.
- **SOC Dashboard:** View investigation statistics, risk distributions, trends, and statuses.
- **PDF Reports:** Generate individual investigation reports and dashboard reports.
- **Authentication:** User registration, login, password hashing, and user-specific investigation access.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Backend | Flask |
| Frontend | HTML, CSS, JavaScript, Bootstrap |
| Database | SQLite |
| ORM | Flask-SQLAlchemy |
| Authentication | Flask-Login |
| CSRF Protection | Flask-WTF |
| Rate Limiting | Flask-Limiter |
| DNS Analysis | dnspython |
| HTTP Requests | Requests |
| PDF Generation | ReportLab |
| Charts | Chart.js |
| Testing | Pytest |
| Development Environment | Kali Linux |

## Project Structure

```text
PhishLens/
│
├── app/
│   ├── routes/
│   │   ├── auth.py
│   │   ├── dashboard.py
│   │   ├── analyzer.py
│   │   └── reports.py
│   │
│   ├── services/
│   │   ├── email_parser.py
│   │   ├── header_analyzer.py
│   │   ├── ioc_analyzer.py
│   │   ├── risk_scorer.py
│   │   ├── attachment_analyzer.py
│   │   ├── dns_analyzer.py
│   │   ├── threat_intel_analyzer.py
│   │   └── domain_threat_analyzer.py
│   │
│   ├── templates/
│   ├── static/
│   ├── extensions.py
│   ├── models.py
│   └── __init__.py
│
├── tests/
├── sample_emails/
├── instance/
├── reports/
├── config.py
├── requirements.txt
├── run.py
├── .env.example
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Sethum164/PhishLens.git
cd PhishLens
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it:

**Linux / Kali Linux:**

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and configure the required environment variables, including a secure, randomly generated `SECRET_KEY`.

If optional external threat intelligence integration is enabled, configure its API credentials as required.

**Important:** Never upload your actual `.env` file, passwords, database files, or API keys to GitHub.

### 5. Initialize the Database

Run:

```bash
python -c "from app import create_app; from app.extensions import db; app = create_app(); app.app_context().push(); db.create_all(); print('Database initialized successfully.')"
```

### 6. Start the Application

```bash
python run.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

Register an account and log in to access the platform.

## Running Tests

PhishLens includes automated tests using Pytest.

Run the complete test suite:

```bash
pytest -v
```

The project includes **39 automated tests**, covering:

- User authentication and registration
- Email analysis and upload validation
- Investigation management and access control
- SOC dashboard statistics and filtering
- PDF report generation and access control

Latest recorded test result: **39 passed**.

## Security Considerations and Limitations

- The application is designed as a cybersecurity learning and demonstration project.
- URL and domain threat checks include heuristic analysis; they do not guarantee detection of every malicious URL or domain.
- SPF, DKIM, and DMARC results are parsed from email authentication headers and are not independently cryptographically verified by PhishLens.
- Attachment analysis examines filename and MIME metadata; it does not perform full malware scanning.
- DNS lookups may disclose queried domains to the configured DNS resolver.
- VirusTotal or other external threat intelligence services may require API credentials and may have usage limits.
- The Flask development server is intended for local development, not production deployment.
- Production deployment requires HTTPS, secure cookie settings, a production WSGI server, and suitable shared rate-limit storage.

Only analyze email samples that you are authorized to inspect. Do not open or execute suspicious attachments.

## Future Improvements

Potential future enhancements include:

- Advanced malware scanning integration
- More external threat intelligence sources
- Improved phishing detection using machine learning
- Advanced IOC correlation
- Enhanced analyst investigation workflows
- Production deployment and monitoring

## Disclaimer

PhishLens is an educational cybersecurity project. Its analysis results are intended to assist security investigations and should not be treated as definitive proof that an email is safe or malicious.

## Author

Developed as a cybersecurity project to explore phishing email analysis, threat detection, IOC extraction, and SOC investigation workflows.

GitHub Repository: https://github.com/Sethum164/PhishLens
