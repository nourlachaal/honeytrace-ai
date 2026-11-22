# HoneyTrace AI — Live Demonstration Runbook

## Before the demo (5 minutes before)

Open three windows side by side:

1. **PowerShell** (for commands)
2. **Browser** with two tabs: `http://localhost:8000/docs` (Swagger) and `http://localhost:8502` (dashboard)
3. **VS Code** (or any editor) with the repo open, to show code when needed

Verify everything is up:
```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/health/db
```
Both should return `{"status":"ok"}`.

If anything is down, restart:
```powershell
# API (kubectl port-forward)
kubectl -n honeytrace port-forward svc/honeytrace-api 8000:8000

# Dashboard (local, latest code)
python -m streamlit run src/dashboard/app.py --server.port 8502
```

---

## Demo script (about 15 minutes)

### Part 1 — The problem (2 min)

**Say:** "HoneyTrace AI is a platform that turns raw honeypot logs into incidents an analyst can investigate. It collects from two sources — Cowrie, an SSH honeypot, and OWASP Juice Shop, a vulnerable web app behind Nginx — normalizes them, detects suspicious behaviour, correlates detections into incidents, and exposes everything through a read-only API."

**Show:** The repository structure briefly (src/collectors, src/detection, src/correlation, src/api, src/dashboard).

### Part 2 — The data (3 min)

**Show the API (Swagger at http://localhost:8000/docs):**

1. Open `/health` → `{"status":"ok"}` (liveness, no DB)
2. Open `/health/db` → `{"status":"ok"}` (readiness)
3. Open `/events` with `limit=5` → show the 13 fields, explain each one
4. Open `/events/{event_id}` with a real ID → show single event
5. Open `/incidents` → show the 8 incidents

**Key talking points:**
- "The API returns exactly 13 approved fields. It never returns raw_event, metadata, command, message or username."
- "This is enforced at two levels: Pydantic models with extra='forbid', and column-level SQL grants to the honeytrace_api role."
- "The database enforces this independently of the code."

**Commands to get real IDs:**
```powershell
# Get a real event ID
python -c "import urllib.request,json; d=json.loads(urllib.request.urlopen('http://127.0.0.1:8000/events?limit=1').read()); print(d['items'][0]['event_id'])"

# Get a real incident ID
python -c "import urllib.request,json; d=json.loads(urllib.request.urlopen('http://127.0.0.1:8000/incidents?limit=1').read()); print(d['items'][0]['incident_id'])"
```

### Part 3 — The dashboard (5 min)

**Open http://localhost:8502**

**Overview tab:**
- Point to the 4 KPI cards. A fresh session loads one page of 50 events, so the cards read 50 / 3 / 2 / 10. The subtitle says it: "aggregated from the loaded page set". The API is cursor-paginated and has no count endpoint by design, so the console reports what it actually loaded and never invents a total.
- Show the sparkline and delta on the Events card
- Show the stacked area chart (Cowrie orange, Juice Shop cyan)
- Show the donut with the loaded event count in the center
- Show top event types (cowrie.command.input: 139 across the full dataset)
- Show top source IPs (172.17.0.1: 312 across the full dataset)
- Show the latest events feed with colored status chips
- To reach the full dataset: drag **Page size** to 200, open **Events**, click **Load more** once (200 + 156 = 356), then return to **Overview**. The cards now read 356 / 25 / 3 / 10, which matches the report.

**Events tab:**
- Click "Events" in the sidebar
- Show the legend (Cowrie orange, Juice Shop cyan)
- Show the table with 50 rows
- Type "cowrie" in the quick filter → show filtering
- Click a filter chip to clear it
- Select a row → show the 13-field detail card + "Raw JSON (same 13 fields)" expander
- Click "Load more" → show next page

**Incidents tab:**
- Click "Incidents" in the sidebar
- Show 4 KPIs: Incidents (8), Open (8), New evidence (0), High or critical (0)
- Show the table with severity stripes (blue = medium) and badges
- Filter by source/status/severity
- Select an incident → show the 8-field detail, summary, caption ("1 detection(s), 15 event(s), 0 missing event(s)")
- Show the vertical timeline (15 entries with timestamps, event types, source dots, detection counts)

**Empty/error states (optional, 1 min):**
- In Incidents, the empty state "No incidents yet" explains the (source, session_id) grouping
- The API unreachable state shows "Cannot reach the API"

### Part 4 — Security (3 min)

**Show the 13-field contract:**
```powershell
.\.venv\Scripts\python.exe scripts\demo_security_proof.py
```
One command prints the health checks, the thirteen approved fields, the forbidden
fields that never appear, the full dataset counts and the incident totals.

**Show the database role:**
```powershell
kubectl -n honeytrace exec deploy/honeytrace-postgres -- psql -U hive -d honeytrace -c "SELECT column_name FROM information_schema.column_privileges WHERE grantee='honeytrace_api' AND table_name='security_events' ORDER BY column_name;"
```
This shows only the 13 public columns are granted.

**Show the API security:**
- Open `/docs` (Swagger) → show the OpenAPI schema
- Try `/events/{id}` with a non-existent ID → 404
- Try `/events?since=2026-01-01` (no timezone) → 400

### Part 5 — Detection and correlation (2 min)

**Show the detection rules:**
```powershell
# Show the 9 rules
python -c "
from src.detection.rules import DEFAULT_RULES, DEFAULT_THRESHOLD_RULES, DEFAULT_SEQUENCE_RULES
for r in DEFAULT_RULES + DEFAULT_THRESHOLD_RULES + DEFAULT_SEQUENCE_RULES:
    print(r.rule_id, '|', r.severity)
"
```

**Show the results:**
- 18 detections: 8 COWRIE_CMD_CHMOD_EXEC, 8 JUICE_LOGIN_FAILED, 1 JUICE_SERVER_ERROR, 1 JUICE_SENSITIVE_ROUTE_SERVED
- 8 incidents, all medium severity, all Cowrie
- Juice Shop detections don't become incidents (no session_id, IP correlation forbidden)

**Show the incident timeline** in the dashboard (already shown in Part 3).

### Part 6 — Testing (1 min)

```powershell
python -m pytest tests/ -q -m "not db"
```
Expected: 263 passed, 5 skipped, 36 deselected.

### Part 7 — Kubernetes (1 min, optional)

```powershell
kubectl get pods -n honeytrace
kubectl get svc -n honeytrace
```
Show 3 pods Running, 3 services.

---

## Key talking points (memorize these)

1. "The API returns exactly 13 approved fields. It never returns raw_event, metadata, command, message or username."
2. "This is enforced at two levels: Pydantic models with extra='forbid', and column-level SQL grants to the honeytrace_api role."
3. "The dashboard has no database credentials. It reads only through the HTTP API."
4. "Incidents are Cowrie-only because Juice Shop events have no session_id. IP-based correlation is deliberately forbidden."
5. "Detections are append-only (database trigger). Incident severity can only rise, never fall."
6. "The detection engine uses explicit, versioned rules, not a black-box model. Every alert can be traced to a rule and the events it cited."
7. "Machine learning (Isolation Forest, DBSCAN) exists offline for comparison but is not in the live pipeline."
8. "263 automated tests pass without a database."

## If something breaks during the demo

| Problem | Fix |
|---|---|
| API unreachable | `kubectl -n honeytrace port-forward svc/honeytrace-api 8000:8000` |
| Dashboard blank | `python -m streamlit run src/dashboard/app.py --server.port 8502` |
| K8s pods down | Start Docker Desktop, wait 60s, `kubectl get pods -n honeytrace` |
| No data in dashboard | Check API: `curl http://127.0.0.1:8000/health/db` |

## After the demo

Close the port-forwards and the dashboard. Do not commit or push. The report is at `report/HoneyTrace_AI_Report.docx`.