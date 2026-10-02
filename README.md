# EDR Telemetry Store Explorer

A browser-based search and investigation tool for querying and analysing EDR telemetry stored in an OpenSearch cluster. Designed for security analysts working with endpoint-detection and response data.

**Current version: 26.08.0.125**

---

## Requirements

Python 3.10 or newer.

## Installation

```bash
pip install -r requirements.txt
```

Dependencies: `flask`, `requests`, `waitress`, `cryptography`

## Running

```bash
python app.py
```

Opens on `http://localhost:5001`

---

## Features

### Search
Build queries with field-value filters or raw DSL JSON. Results display as collapsible event cards (Results tab) or a sortable, filterable table (Table tab).

### Table View
Click any row to open a full event-detail panel. Right-click any cell or detail field to add include/exclude filters, jump to the Story Graph, add to a column set, or send to Group By.

### Column Sets
Switch between predefined column sets — Process, Network, File, DNS, Registry, ScheduleTask, Script — or build custom sets in Settings. Each set loads its predefined filter templates automatically.

### Group By
Aggregate events by one or more fields. Right-click any cell → **Add to Group By**, or type field names manually. Results show event count, unique host count (cardinality), and first/last seen timestamps per bucket. Click a row to filter; right-click to include or exclude. Multiple fields use OpenSearch `multi_terms`.

### Hunt
Paste free-form threat-intelligence text (file paths, hashes, domains, IPs, registry keys, mutexes, URLs) or structured CSV (`Indicator_type,Data,Note`) and run it as a single search across all IOC types.

- **Step 1** — aggregation-only query produces the **Affected Hosts** table: host, maGuid, systemUniqueID, event count, first seen, last seen — accurate across the full time range.
- **Step 2** — click **Load matching events** to load event cards on demand.
- Right-click any Affected Hosts cell to add include/exclude filters.
- Right-click **First Seen** → add a `time ≥` filter; right-click **Last Seen** → add a `time ≤` filter.
- Saved hunts persist in `ets_explorer_custom.json`.

### OpenIOC
Run FireEye/Trellix `.ioc` files directly against the EDR Telemetry cluster. Browse a file tree of the local `OpenIOC/` directory organized by MITRE ATT&CK tactic, OS platform, and confidence level. Select individual files or entire folders and run them as a single search.

- Parses the boolean AND/OR criteria tree and converts it to an OpenSearch `bool` query.
- Always 2 OpenSearch queries regardless of how many files are selected — all IOC criteria are combined into one `bool.should`, then each matching event is attributed back to the specific IOC file(s) that triggered it via client-side re-evaluation.
- Step 1 shows an **Affected Hosts** table (host, maGuid, systemUniqueID, event count, first/last seen). Step 2 loads event cards on demand.
- IOC badge labels on every event card show which `.ioc` file matched.

### Story Graph
Renders the parent-child trace chain of an event as a directed graph for following attack chains through EDR telemetry.

### Query Optimisation
Analyses the active query and suggests index mappings, composite aggregations, and date-histogram rollups to improve search performance.

### Code Generation
Python and PowerShell tabs emit ready-to-run SDK snippets reproducing the current search exactly.

### Live Tail
Polls for new events with high-watermark and client-side `_id` deduplication. Table sorts by Time descending while tail is active.

### Server Groups
Group multiple servers and query them simultaneously. Results are merged and sorted. Manage groups in Settings → Server Groups.

### mTLS
Connect over mutual TLS. Paste the full `show certificates hxclient` output — CA, client cert, and key are detected and saved automatically, encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256). Decryption happens in memory only at connect time.

---

## Settings Persistence

| File | Contents |
|------|----------|
| `ets_explorer_core_setting.json` | Hunt type definitions, column sets, predefined filter defaults |
| `ets_explorer_custom.json` | Server groups, custom column sets, saved hunts |

---

## Files

| Path | Purpose |
|------|---------|
| `app.py` | Flask/Waitress backend |
| `templates/index.html` | Single-page frontend (HTML + CSS + JS) |
| `requirements.txt` | Python dependencies |
| `readme.txt` | Plain-text readme |
| `release_notes.txt` | Change history |
| `certs/` | Encrypted certificate storage (auto-created) |
| `certs/.key` | Fernet encryption key — do not share or commit |
| `access.log` | HTTP access log, rotates at 20 MB × 5 files |

---

## License

MIT License — Copyright © 2026
