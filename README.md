# FraudShield AI — Government Welfare Fraud Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange?logo=scikitlearn)
![Docker](https://img.shields.io/badge/Docker-ready-blue?logo=docker)
![License](https://img.shields.io/badge/License-MIT-green)

> **An AI-powered fraud detection platform for government welfare scheme applications**, combining supervised machine learning, rule-based engines, and advanced forensics to identify fraudulent welfare claims in real time.

---

## Features

| Feature | Description |
|---|---|
| **Hybrid ML Engine** | RandomForestClassifier + IsolationForest ensemble (70% rules + 30% ML) |
| **13-Point Rule Engine** | Duplicate Aadhaar, phone reuse, income threshold, age validation & more |
| **3D Network Analysis** | Three.js WebGL graph of fraud rings and entity connections |
| **ML Model Metrics** | Live accuracy, precision, recall, F1, confusion matrix, feature importances |
| **REST API** | Full OpenAPI/Swagger docs at `/api/docs` |
| **Admin Console** | Manual approve/reject with role-based access control |
| **Citizen Reporting** | Public fraud reporting portal with admin review workflow |
| **Audit Trail** | Complete action logging for every decision |
| **Blacklist/Whitelist** | Entity-level block/fast-track lists |
| **Server-Side Pagination** | Handles thousands of records efficiently |
| **Deepfake Detection** | Simulated face spoof and deepfake analysis |
| **Document Forgery** | AI-simulated document authenticity scoring |
| **Bot Detection** | Behavioral mouse/typing pattern analysis |
| **Security Logs** | Per-user login attempt and session tracking |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0 |
| ML | scikit-learn 1.4 (RandomForest + IsolationForest) |
| Database | SQLite (development) / PostgreSQL-ready |
| Frontend | Bootstrap 5, Three.js, Chart.js |
| Auth | Session-based with OTP email verification |
| API Docs | Flasgger (Swagger UI) |
| Production | Gunicorn WSGI server |
| Container | Docker + Docker Compose |

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-username/fraudshield.git
cd fraudshield

# Build and run
docker-compose up --build

# Open in browser
http://localhost:5000
```

### Option 2: Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

---

## API Reference

Swagger UI available at: `http://localhost:5000/api/docs`

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/stats` | GET | Dashboard statistics (total, approved, rejected, fraud rate) |
| `/api/v1/applications` | GET | Paginated list with search and classification filter |
| `/api/v1/applications/<id>` | GET | Single application details |
| `/api/v1/classify` | POST | Score any payload without saving (demo endpoint) |
| `/api/v1/ml-metrics` | GET | RandomForest model accuracy, F1, feature importances |

### Example API Call

```bash
curl -X POST http://localhost:5000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Ravi Kumar",
    "aadhaar": "123456789012",
    "phone": "9876543210",
    "income": 180000,
    "address": "12 MG Road, Bangalore",
    "scheme": "PM-KISAN",
    "age": 45,
    "district": "Bangalore Rural"
  }'
```

Response:
```json
{
  "classification": "APPROVE",
  "risk_level": "LOW",
  "risk_score": 12,
  "ml_score": 3,
  "rule_score": 9,
  "reasons": ["No fraud indicators detected"],
  "checks_performed": 13
}
```

---

## Architecture

```
fraudshield/
+-- app.py                  # Flask routes + REST API
+-- fraud_detector.py       # ML engine (RF + IsolationForest)
+-- database.py             # SQLite queries + migrations
+-- ai_simulator.py         # AI simulation modules
+-- network_analyzer.py     # Graph/network fraud ring detection
+-- user_manager.py         # Auth and session management
+-- templates/
|   +-- admin/
|   |   +-- ml_metrics.html # ML model dashboard
|   |   +-- reports.html    # Citizen reports console
|   |   +-- manual_approve.html  # Manual override console
|   +-- dashboard.html      # Main intelligence dashboard
|   +-- details.html        # Application deep-dive
|   +-- network_analysis.html  # 3D WebGL network graph
+-- static/
|   +-- css/style.css       # Cyber-Intelligence dark theme
|   +-- js/three_visuals.js # Three.js 3D visualizations
+-- Dockerfile
+-- docker-compose.yml
+-- requirements.txt
+-- tests/
    +-- test_app.py         # Flask integration tests
    +-- test_fraud_detector.py  # ML unit tests
```

---

## ML Model Details

The fraud scoring uses a **two-model ensemble**:

| Model | Type | Contribution |
|---|---|---|
| `RandomForestClassifier` | Supervised (200 estimators) | 15/30 ML score points |
| `IsolationForest` | Unsupervised anomaly | 15/30 ML score points |

**7 Input Features:**
1. Income amount
2. Duplicate Aadhaar count
3. Address similarity score
4. Phone reuse count
5. Suspicious name flag
6. Address quality flag
7. Age risk flag

**Final Score = 70% Rule Score + 30% ML Score**

| Score | Classification | Risk Level |
|---|---|---|
| 0–39 | APPROVE | LOW |
| 40–69 | REVIEW | MEDIUM |
| 70–100 | REJECT | HIGH |

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Default Login

| Role | Username | Password |
|---|---|---|
| Admin | admin | admin123 |
| Officer | officer1 | officer123 |

> Change all credentials before deploying to production.

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

> Built with Python, Flask, scikit-learn and Three.js | Government Welfare Fraud Detection
