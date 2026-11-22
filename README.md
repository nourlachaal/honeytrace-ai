# 🍯 HoneyTrace AI

**HoneyTrace AI** is a cybersecurity telemetry, detection, and incident-correlation platform designed to transform raw security logs into **structured, explainable, and actionable security information**.

The platform collects telemetry from two complementary sources:

- **Cowrie** — SSH/Telnet honeypot
- **OWASP Juice Shop** — intentionally vulnerable web application behind Nginx

The collected data is normalized, stored in PostgreSQL, analyzed by an explainable rule-based detection engine, correlated into incidents, and exposed through a restricted **FastAPI** API and a **Streamlit** dashboard.

> **Academic cybersecurity project — FSS**

---

## 📌 Table of Contents

- [Project Overview](#-project-overview)
- [Architecture](#-architecture)
- [Main Components](#-main-components)
- [Data Flow](#-data-flow)
- [Security Design](#-security-design)
- [Detection and Correlation](#-detection-and-correlation)
- [Machine Learning](#-machine-learning)
- [Current Dataset](#-current-dataset)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Running the Project](#-running-the-project)
- [API](#-api)
- [Dashboard](#-dashboard)
- [Security Demonstration](#-security-demonstration)
- [Testing](#-testing)
- [Kubernetes](#-kubernetes)
- [Troubleshooting](#-troubleshooting)
- [Current Limitations](#-current-limitations)
- [Future Improvements](#-future-improvements)

---

# 🔎 Project Overview

Security tools often generate large amounts of raw telemetry that can be difficult to analyze directly.

HoneyTrace AI addresses this problem by transforming raw telemetry into a structured pipeline:

```text
Raw Security Logs
       │
       ▼
┌───────────────────────┐
│       Collectors      │
│                       │
│ Cowrie / Juice Shop   │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│     Normalization     │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│      PostgreSQL       │
│   Source of Truth     │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│   Detection Engine    │
│    Rule-based IDS     │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Correlation Engine   │
│   Detection → Incident│
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│       FastAPI         │
│   Read-only API       │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│      Streamlit        │
│      Dashboard        │
└───────────────────────┘
```

The main objective is to provide analysts with **explainable detections and incidents without exposing unnecessary sensitive information**.

---

# 🏗️ Architecture

```text
                 ┌──────────────────┐
                 │      Cowrie      │
                 │ SSH/Telnet       │
                 │ Honeypot         │
                 └────────┬─────────┘
                          │
                          │
                          ▼
                 ┌──────────────────┐
                 │    Collectors    │
                 └────────┬─────────┘
                          │
                          │
┌──────────────────┐      │
│  Juice Shop      │──────┘
│ Vulnerable Web   │
│ App + Nginx      │
└──────────────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │   Normalization  │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    PostgreSQL    │
                 │  Source of Truth │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Detection Engine │
                 │ 9 implemented    │
                 │ rules             │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │ Correlation      │
                 │ Engine           │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │     FastAPI      │
                 │ Read-only API    │
                 └────────┬─────────┘
                          │
                          ▼
                 ┌──────────────────┐
                 │    Streamlit     │
                 │    Dashboard     │
                 └──────────────────┘
```

---

# 🧩 Main Components

## 🐚 Cowrie

Cowrie is used as the SSH/Telnet honeypot.

It generates telemetry such as:

- connection events
- authentication attempts
- commands
- command sequences
- session information

Cowrie provides session IDs, which allows HoneyTrace AI to correlate multiple detections belonging to the same attacker session.

---

## 🛒 OWASP Juice Shop

OWASP Juice Shop is an intentionally vulnerable web application.

In this project it is used as a **web telemetry source**, not as a traditional honeypot.

Its telemetry is collected through the web application/Nginx layer.

Examples include:

- failed login attempts
- server errors
- sensitive routes being served

Juice Shop events currently do not contain session IDs suitable for the project's correlation strategy.

Therefore, Juice Shop detections remain standalone detections and are not converted into incidents.

---

# 🔄 Data Flow

The complete processing pipeline is:

```text
Cowrie / Juice Shop
        │
        ▼
     Collectors
        │
        ▼
   Normalization
        │
        ▼
    PostgreSQL
        │
        ▼
 Detection Engine
        │
        ▼
 Correlation Engine
        │
        ▼
     FastAPI
        │
        ▼
   Streamlit UI
```

---

# 🧹 Normalization

Different security sources produce different log formats.

Normalization converts them into a common event structure.

The normalization layer:

- validates timestamps
- extracts common fields
- converts source-specific data
- stores additional information in metadata
- masks sensitive keys
- validates incoming events

This allows the detection engine to work with a consistent structure regardless of the original source.

---

# 🔐 Data Minimization

HoneyTrace AI deliberately limits the amount of information exposed outside the database.

The public API exposes exactly **13 approved fields**.

Sensitive/internal fields such as:

```text
raw_event
metadata
command
message
username
```

are not exposed by the API.

The architecture follows a one-way reduction of data exposure:

```text
Raw telemetry
     ↓
Normalization
     ↓
Database
     ↓
Detection / Correlation
     ↓
Restricted API
     ↓
Dashboard
```

---

# 🔑 Idempotent Event Ingestion

HoneyTrace AI generates a deterministic `event_id` using **SHA-256** over canonicalized event data.

This makes event ingestion idempotent.

If the same event is processed again, it does not create a duplicate record.

Conceptually:

```text
Same event
   │
   ▼
Same canonical representation
   │
   ▼
Same SHA-256
   │
   ▼
Same event_id
   │
   ▼
Duplicate rejected
```

The database uses:

```sql
ON CONFLICT (event_id) DO NOTHING
```

to prevent duplicate insertion.

---

# 🗃️ PostgreSQL

PostgreSQL is the **source of truth** for the platform.

It stores:

- security events
- detections
- incidents

The database is accessed through controlled application layers rather than directly from the dashboard.

---

# 🚨 Detection and Correlation

## Detection Engine

The detection engine is primarily **rule-based and explainable**.

Rules are explicit and versioned.

Each detection can be traced back to:

- the detection rule
- the source event
- the severity
- the evidence supporting the detection

The current implementation contains **9 detection rules**, although only some of them fire on the current dataset.

---

## Current Detection Results

The current dataset contains:

| Detection rule | Count |
|---|---:|
| `COWRIE_CMD_CHMOD_EXEC` | 8 |
| `JUICE_LOGIN_FAILED` | 8 |
| `JUICE_SERVER_ERROR` | 1 |
| `JUICE_SENSITIVE_ROUTE_SERVED` | 1 |
| **Total** | **18** |

Therefore:

```text
18 detections
      ↓
8 incidents
```

---

# 🔗 Correlation

The current correlation strategy groups detections using:

```text
(source, session_id)
```

Cowrie provides session IDs, so Cowrie detections can be correlated into incidents.

Juice Shop events currently do not provide the required session ID.

Therefore:

```text
Cowrie
  │
  ├── detection
  ├── detection
  └── detection
          │
          ▼
       Incident
```

while:

```text
Juice Shop
  │
  ├── detection
  ├── detection
  └── detection

(no session_id)
       │
       ▼
Standalone detections
```

IP-based correlation is deliberately not used.

---

# 🤖 Machine Learning (advisory)

Machine learning is **advisory** and runs inside the live pipeline (`src/pipeline.py`).
It never changes a detection or an incident on its own.

The project includes:

- **Isolation Forest** (`src/ml/isolation_forest.py`) — `SessionAnomalyDetector`,
  contamination 0.1, 100 estimators, model version 1.2.0, artifact format 1.
- **DBSCAN** (`src/ml/dbscan.py`) — experimental/offline comparison.
- 9 numeric session features (`src/ml/features.py`): `event_count`,
  `login_failed_count`, `login_success_count`, `command_count`,
  `distinct_event_types`, `distinct_usernames`, `duration_seconds`,
  `events_per_second`, `failed_login_ratio`. No text, no rule output (no leakage).

The live detection pipeline still relies on explicit, explainable rules for
detections and incidents. ML adds a **session-level anomaly signal** that the
dashboard surfaces per incident:

- `/ml/status` exposes `model_trained`, `model_loaded`, `model_source`,
  `sessions_scored`, `anomalies_found`, `anomaly_type` (`isolation_forest`),
  `anomaly_threshold` and `anomaly_sessions` (each with `score`, `threshold`,
  `criticality`, `category` and the session `features`).
- Criticality is an advisory percentile band of the anomaly score:
  critical (≥99th), high (≥95th), medium (≥85th), low (else).
- Anomaly category describes the dominant behaviour: `command_execution`,
  `failed_login_burst`, `web_request`, `session_behaviour`.

An anomaly is **not** a confirmed attack — it is a signal to investigate.

---

# 📊 Current Dataset

The current demonstration dataset contains:

| Metric | Value |
|---|---:|
| Events | **356** |
| Sessions | **25** |
| Source IPs | **3** |
| Detections | **18** |
| Incidents | **8** |
| Cowrie events | **339** |
| Juice Shop events | **17** |
| Detection rules implemented | **9** |
| Public API fields | **13** |

All current incidents are Cowrie incidents because Juice Shop events cannot currently be correlated using the `(source, session_id)` strategy.

---

# 🛡️ Security Design

HoneyTrace AI uses several security controls.

## Least Privilege

The `honeytrace_api` PostgreSQL role is restricted to the approved public columns.

The API does not receive unrestricted database access.

---

## Two-Level API Protection

The 13-field API contract is enforced at two levels:

### Application level

Pydantic models use:

```python
extra="forbid"
```

### Database level

Column-level SQL privileges restrict what the API role can access.

This means the database independently enforces the data exposure boundary.

---

## Dashboard Isolation

The Streamlit dashboard does **not** have database credentials.

The architecture is:

```text
Streamlit
    │
    │ HTTP
    ▼
 FastAPI
    │
    │ SQL
    ▼
PostgreSQL
```

The dashboard therefore cannot directly query PostgreSQL.

---

## Append-Only Detections

Detection records are append-only.

A database trigger protects the historical detection evidence.

This prevents existing detection records from being silently modified.

---

## Monotonic Incident Severity

Incident severity can increase but cannot silently decrease.

For example:

```text
Medium
  ↓
High
  ↓
Critical
```

but not:

```text
Critical
  ↓
Medium
```

without an explicit process.

---

## Quarantine

Malformed or rejected input is quarantined without storing the original sensitive content.

The system records information such as:

- hash
- line information
- rejection reason
- timestamp

This allows rejected input to be tracked without unnecessarily storing its contents.

---

## Pagination

The API uses cursor-based pagination for event retrieval.

This prevents the dashboard from requesting the entire dataset at once and is better suited to datasets that continue to grow.

---

## Database Timeout

Database statements have a **5-second timeout**.

This limits the impact of unexpectedly long-running database operations.

---

# 🌐 API

The FastAPI service provides read-only endpoints.

## Health

```http
GET /health
```

Basic liveness check.

Expected response:

```json
{
  "status": "ok"
}
```

---

## Database Health

```http
GET /health/db
```

Checks database readiness/connectivity.

Expected response:

```json
{
  "status": "ok"
}
```

---

## Events

```http
GET /events
```

Returns cursor-paginated security events.

Example:

```http
GET /events?limit=5
```

---

## Single Event

```http
GET /events/{event_id}
```

Returns one event.

A non-existent event returns:

```text
404
```

---

## Incidents

```http
GET /incidents
```

Returns incidents.

---

## Single Incident

```http
GET /incidents/{incident_id}
```

Returns one incident.

---

## ML Status

```http
GET /ml/status
```

Provides the current ML status (advisory). Returns `enabled`, `model_loaded`,
`model_trained`, `model_version`, `detector_version`, `sessions_evaluated`,
`sessions_scored`, `detections_scored`, `anomalies_found`, `inference_success`,
`inference_executed`, `persistence_status`, `model_source`, `status`,
`events_total`, `sessions_total`, `last_inference_at`, `inference_error`,
`anomaly_type`, `anomaly_threshold` and `anomaly_sessions` (per-session score,
threshold, criticality, category and features).

---

# 📚 Swagger Documentation

FastAPI automatically exposes OpenAPI/Swagger documentation.

Once the API is running:

```text
http://localhost:8000/docs
```

This interface can be used to demonstrate:

- health checks
- event retrieval
- event details
- incident retrieval
- incident details
- API validation
- response schemas

---

# 📈 Dashboard

The project uses **Streamlit** for the dashboard.

Default demonstration URL:

```text
http://localhost:8502
```

The dashboard contains three main sections:

```text
Overview
Events
Incidents
```

---

## Overview

The Overview page displays:

- KPI cards (events, detections, incidents, sessions)
- event statistics and an events-over-time chart
- source distribution
- top event types
- top source IPs
- latest events
- an **ML monitoring** section (`/ml/status`): model trained/loaded, versions,
  sessions scored, anomalies found, inference success, persistence status,
  model source, advisory anomaly sessions

A fresh session initially loads one page of 50 events.

Therefore, the initial KPI cards represent the **loaded page set**, not necessarily the complete database.

To load the complete demonstration dataset:

1. Set **Page size** to `200`
2. Open **Events**
3. Click **Load more**
4. Return to **Overview**

The dashboard then loads:

```text
356 events
25 sessions
3 source IPs
10 event types
```

---

## Events

The Events page provides:

- event table
- quick filtering
- filter chips
- event details
- 13-field event representation
- pagination
- Load More functionality

The event detail view exposes the same approved 13-field contract.

---

## Incidents

The Incidents page provides:

- incident KPIs (including an **ML anomalies** card)
- incident table with a severity column and an **ML** column
  (anomaly category + criticality chip)
- severity indicators (escalated when the advisory ML flags the session as
  critical/high)
- filtering by source / status / severity
- incident details (8 core fields + ML anomaly block + session features +
  ML run details)
- incident timeline

The current dataset contains:

```text
7 incidents
7 open
0 new evidence
1 high/critical   (the session flagged critical by the advisory ML model)
1 ML anomaly      (session 7b08bd8296a1, category command_execution, critical)
```

The remaining incidents are medium-severity Cowrie incidents. Severity can only
rise (DB trigger) and is never lowered by ML.

---

# 🧪 Security Demonstration

The repository contains a security demonstration script:

```powershell
.\.venv\Scripts\python.exe scripts\demo_security_proof.py
```

The script demonstrates:

- health checks
- approved API fields
- forbidden fields
- dataset counts
- incident totals

---

## Database Permission Proof

To inspect the columns granted to `honeytrace_api`:

```powershell
kubectl -n honeytrace exec deploy/honeytrace-postgres -- psql -U hive -d honeytrace -c "SELECT column_name FROM information_schema.column_privileges WHERE grantee='honeytrace_api' AND table_name='security_events' ORDER BY column_name;"
```

This should show the approved public columns.

---

# 🧪 API Security Tests

The API can also be tested manually.

### Non-existent event

Call:

```http
GET /events/{invalid_event_id}
```

Expected:

```text
404 Not Found
```

### Invalid timestamp

For example:

```http
GET /events?since=2026-01-01
```

without a timezone.

Expected:

```text
400 Bad Request
```

This demonstrates API input validation.

---

# 🧪 Automated Tests

Run:

```powershell
python -m pytest tests/ -q -m "not db"
```

Expected result:

```text
263 passed
5 skipped
36 deselected
```

The test suite can therefore validate the application without requiring a database for the non-DB tests.

---

# 📁 Project Structure

```text
HoneyTrace-AI/
│
├── src/
│   ├── api/
│   │   └── ...
│   │
│   ├── collectors/
│   │   ├── cowrie/
│   │   └── juice_shop/
│   │
│   ├── correlation/
│   │
│   ├── dashboard/
│   │   └── app.py
│   │
│   ├── detection/
│   │   └── rules.py
│   │
│   ├── ml/
│   │
│   ├── normalization/
│   │
│   ├── storage/
│   │
│   └── pipeline.py
│
├── scripts/
│   └── demo_security_proof.py
│
├── sql/
│   └── migrations/
│
├── k8s/
│   ├── namespace.yaml
│   ├── postgres.yaml
│   ├── api.yaml
│   ├── dashboard.yaml
│   ├── pg-secret.yaml
│   ├── streamlit-configmap.yaml
│   └── pipeline-cronjob.yaml
│
├── tests/
│
├── docs/
│
├── report/
│   └── HoneyTrace_AI_Report.docx
│
├── requirements.txt
├── requirements-ml.txt
├── .env.example
├── Dockerfile
└── docker-compose.yml
```

---

# 💻 Requirements

The project is designed to run on Windows/Linux with:

- Python
- Docker Desktop
- Kubernetes / `kubectl`
- PostgreSQL through the project deployment
- Git

For the complete Kubernetes demonstration, Docker Desktop with Kubernetes enabled is required.

---

# ⚙️ Installation

## 1. Clone the repository

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd HoneyTrace-AI
```

---

## 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell activation is not available, the project Python executable can be called directly:

```powershell
.\.venv\Scripts\python.exe
```

---

## 3. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

---

## 4. Install dependencies

Install the main dependencies:

```powershell
python -m pip install -r requirements.txt
```

Install the ML dependencies:

```powershell
python -m pip install -r requirements-ml.txt
```

---

# 🐳 Docker

Start the local services with:

```powershell
docker compose up -d
```

Check the containers:

```powershell
docker compose ps
```

Stop them with:

```powershell
docker compose down
```

---

# ☸️ Kubernetes Deployment

The project also contains Kubernetes manifests.

Check the cluster:

```powershell
kubectl get nodes
```

Create/apply the HoneyTrace namespace and resources according to the manifests in:

```text
k8s/
```

Then check:

```powershell
kubectl get pods -n honeytrace
```

and:

```powershell
kubectl get svc -n honeytrace
```

The demonstration environment contains:

```text
3 Running pods
3 services
```

---

# 🚀 Running the API

For the Kubernetes demonstration, expose the API locally using:

```powershell
kubectl -n honeytrace port-forward svc/honeytrace-api 8000:8000
```

The API is then available at:

```text
http://localhost:8000
```

Swagger:

```text
http://localhost:8000/docs
```

Health check:

```powershell
curl http://127.0.0.1:8000/health
```

Database health check:

```powershell
curl http://127.0.0.1:8000/health/db
```

Expected:

```json
{"status":"ok"}
```

---

# 🖥️ Running the Dashboard

Run Streamlit locally with:

```powershell
python -m streamlit run src/dashboard/app.py --server.port 8502
```

The dashboard is then available at:

```text
http://localhost:8502
```

---

# 🔎 Getting a Real Event ID

PowerShell:

```powershell
python -c "import urllib.request,json; d=json.loads(urllib.request.urlopen('http://127.0.0.1:8000/events?limit=1').read()); print(d['items'][0]['event_id'])"
```

Use the returned ID with:

```text
GET /events/{event_id}
```

---

# 🔎 Getting a Real Incident ID

```powershell
python -c "import urllib.request,json; d=json.loads(urllib.request.urlopen('http://127.0.0.1:8000/incidents?limit=1').read()); print(d['items'][0]['incident_id'])"
```

Use the returned ID with:

```text
GET /incidents/{incident_id}
```

---

# 🔍 Viewing Detection Rules

The project contains three categories of detection rules:

- default rules
- threshold rules
- sequence rules

To display the implemented rules:

```powershell
python -c "from src.detection.rules import DEFAULT_RULES, DEFAULT_THRESHOLD_RULES, DEFAULT_SEQUENCE_RULES; [print(r.rule_id, '|', r.severity) for r in DEFAULT_RULES + DEFAULT_THRESHOLD_RULES + DEFAULT_SEQUENCE_RULES]"
```

The current implementation contains:

```text
9 rules
```

---

# 🧪 Live Demonstration

A complete demonstration can be performed using three windows:

```text
┌─────────────────┐
│   PowerShell    │
│                 │
│ Commands / K8s  │
└─────────────────┘

┌─────────────────┐
│     Browser     │
│                 │
│ Swagger         │
│ Dashboard       │
└─────────────────┘

┌─────────────────┐
│     VS Code     │
│                 │
│ Source code     │
└─────────────────┘
```

Recommended demonstration order:

1. Explain the problem
2. Show repository architecture
3. Show `/health`
4. Show `/health/db`
5. Show `/events`
6. Show `/incidents`
7. Show the dashboard
8. Demonstrate security controls
9. Show detection rules
10. Show correlation
11. Run automated tests
12. Optionally show Kubernetes

---

# ⚠️ Troubleshooting

## API unreachable

Run:

```powershell
kubectl -n honeytrace port-forward svc/honeytrace-api 8000:8000
```

Then test:

```powershell
curl http://127.0.0.1:8000/health
```

---

## Dashboard blank

Run:

```powershell
python -m streamlit run src/dashboard/app.py --server.port 8502
```

Then open:

```text
http://localhost:8502
```

---

## Kubernetes pods are down

Make sure Docker Desktop is running.

Then:

```powershell
kubectl get pods -n honeytrace
```

Wait for the pods to become:

```text
Running
```

---

## Dashboard contains no data

Check:

```powershell
curl http://127.0.0.1:8000/health/db
```

If the database health check fails, inspect:

```powershell
kubectl get pods -n honeytrace
kubectl get svc -n honeytrace
```

---

# 🚧 Current Limitations

The current implementation has several deliberate limitations.

### No automatic blocking

HoneyTrace AI detects and reports suspicious activity.

It does not automatically:

- block IP addresses
- terminate sessions
- modify firewall rules
- attack back
- respond automatically to attackers

---

### Juice Shop correlation

Juice Shop telemetry currently lacks the session identifier required by the current correlation strategy.

Therefore, its detections remain standalone.

---

### Cross-source correlation

Cross-source correlation between Cowrie and Juice Shop is not currently implemented.

---

### API exposure

The API deliberately exposes only a restricted set of fields.

Raw evidence remains internal.

---

# 🚀 Future Improvements

Potential future improvements include:

- HTTP session identification
- cross-source correlation
- improved secret detection inside free-text fields
- additional detection rules
- improved ML integration
- automated response mechanisms
- Kubernetes NetworkPolicies
- Kubernetes RBAC hardening
- larger-scale telemetry ingestion
- additional security telemetry sources

---

# 📄 Project Report

The complete project report is available at:

```text
report/HoneyTrace_AI_Report.docx
```

---

# 🎯 Project Summary

HoneyTrace AI transforms raw security telemetry into structured security intelligence:

```text
        RAW TELEMETRY
              │
              ▼
         COLLECTION
              │
              ▼
        NORMALIZATION
              │
              ▼
          STORAGE
        PostgreSQL
              │
              ▼
         DETECTION
        9 rule-based
           rules
              │
              ▼
        CORRELATION
              │
              ▼
          INCIDENTS
              │
              ▼
          FASTAPI
        13 public fields
              │
              ▼
         STREAMLIT
          DASHBOARD
```

The platform emphasizes:

- **Explainability**
- **Least privilege**
- **Data minimization**
- **Defense in depth**
- **Secure API design**
- **Traceable detections**
- **Controlled data exposure**
- **Incident correlation**

---

## 📊 Demonstration Snapshot

```text
356 Events
25 Sessions
3 Source IPs
18 Detections
8 Incidents
9 Detection Rules
13 Public API Fields
263 Automated Tests Passed
```

HoneyTrace AI is designed as an academic cybersecurity platform demonstrating how raw honeypot and application telemetry can be transformed into controlled, explainable security detections and incidents.
