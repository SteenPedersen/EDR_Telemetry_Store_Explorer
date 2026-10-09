# EDR Telemetry Store Explorer

A browser-based search and investigation tool for querying and analysing EDR telemetry stored in an OpenSearch cluster. Designed for security analysts working with endpoint-detection and response data.

**Current version: 26.10.0.131**

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

## Connecting to OpenSearch

1. Open the **Connection Settings** panel (gear icon or Settings tab).
2. Enter the server name and OpenSearch URL (e.g. `https://host:9200`).
3. Add the certificate if required (see **TLS / mTLS** below).
4. Click **Connect**.

On a successful connection the cluster name, version, and available indices are displayed. If the index list is not available due to permissions, type the index name or pattern manually.

---

## TLS / mTLS

If your OpenSearch cluster requires client certificates:

**Option A — Paste All Certificates (recommended)**
Paste the full output of the appliance command `show certificates hxclient`. The CA certificate, client certificate, and private key are detected automatically. Certificates are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) and stored as `.enc` files under `certs/<server-name>/`. Decryption happens in memory only during the TLS handshake; no plaintext is written to disk.

**Option B — Individual `.pem` file paths**
Enter the full paths to the CA certificate, client certificate, and client key in the Individual file paths section.

Enable **Skip hostname verification** if the server certificate does not match the hostname (e.g. self-signed certs).

---

## Features

### Search
Build queries with field-value filters or raw DSL JSON. Results display as collapsible event cards (Results tab) or a sortable, filterable table (Table tab).

### Table View
Click any row to open a full event-detail panel. Right-click any cell or detail field to add include/exclude filters, jump to the Story Graph, add to a column set, or send to Group By. Copy any event as raw JSON or CSV from the card header buttons.

The detail panel is resizable by dragging its left edge; width persists across sessions.

### Column Sets
Switch between predefined column sets — Process, Network, File, DNS, Registry, ScheduleTask, Script — or build custom sets in Settings. Each set loads its predefined filter templates automatically.

### Group By
Aggregate events by one or more fields. Right-click any cell → **Add to Group By**, or type field names manually. Results show event count, unique host count (cardinality), and first/last seen timestamps per bucket. Click a row to filter; right-click to include or exclude. Multiple fields use OpenSearch `multi_terms`. Export results as CSV.

### Hunt

Paste free-form threat-intelligence text (file paths, hashes, domains, IPs, registry keys, mutexes, URLs) or structured CSV (`Indicator_type,Data,Note`) and run it as a single search across all IOC types simultaneously.

**IOC auto-detection**
- SHA256 (64 hex chars), SHA1 (40 hex chars), MD5 (32 hex chars) identified automatically.
- IPv4 addresses, domains, URLs, registry keys, file paths, process names, and command lines.
- Defanged indicators are normalised (`hxxps`, `[.]`, `[://]`, `(.)`) before matching.

**IOC type prefix override (free-text mode)**
Force a specific type for a line by prefixing it with a keyword:
```
sha256,b25b87cfcedc69e27570afa1f4b1ca85aab07fd416c5d0228f1fe32886e0a9a6,PortStarter DLL
ip address ,5.39.222.67 ,C2 Server
file,DF0E2D20B4E8473699.TMP
```
Supported keywords: `sha256`, `sha1`, `md5`, `ip`, `domain`, `dns`, `url`, `registry_path_key`, `file`, `filename`, `file_path_name`.

**Two-phase search**
- **Step 1** — aggregation-only query produces the **Affected Hosts** table: host, maGuid, systemUniqueID, event count, first seen, last seen. Accurate across the full time range.
- **Step 2** — click **Load Matching Events** to fetch event cards on demand. The search is automatically scoped to the matched-host set from Step 1, so it only queries relevant data.
- **Per-host drill-down** — each row in the Affected Hosts table has a **▶** button to load events for that single host without rerunning all IOC queries.

**Results**
- Event cards show color-coded event-type badges (EXEC, NET, DNS, FWRT, etc.) matching the Table view.
- IOC match badge on every card shows the specific matched value.
- Right-click any Affected Hosts cell for include/exclude filters, Story Graph, Group By.
- Right-click **First Seen** → add a `time ≥` filter; right-click **Last Seen** → add a `time ≤` filter.

**Input box**
- The IOC text box auto-expands as you add more lines and stays at a minimum of 10 rows.
- Collapse or expand the input box with the **Collapse Hunt Box / Expand Hunt Box** button in the toolbar — useful once a hunt is running and you want to see the results without scrolling.
- IOC text is color-coded in-place as you type. Drag-and-drop a file to load its contents.
- Multiple tabs let you run parallel investigations.
- Saved hunts persist in `ets_explorer_custom.json`.

Active sidebar filters and the current time range are applied when running a hunt, so results are scoped to the same dataset as the main search.

### OpenIOC
Run FireEye / Trellix `.ioc` files directly against the EDR Telemetry cluster. Browse a file tree of the local `OpenIOC/` directory organised by MITRE ATT&CK tactic, OS platform, and confidence level. Select individual files or entire folders and run them as a single search.

- Parses the boolean AND/OR criteria tree and converts it to an OpenSearch `bool` query.
- Always exactly 2 OpenSearch queries regardless of how many files are selected — all IOC criteria are combined into one `bool.should`, then each matching event is attributed back to the specific `.ioc` file(s) that triggered it via client-side re-evaluation.
- Step 1 shows an **Affected Hosts** table; Step 2 loads event cards on demand with IOC badge labels.
- Right-click Affected Hosts cells for the standard context menu.

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

### Dark / Light Mode
Toggle with the sun/moon button in the top bar; preference is persisted.

---

## MCP Server (Claude Integration)

`mcp_hunt_server.py` exposes Hunt as an MCP tool so Claude can search your EDR telemetry mid-conversation.

### Setup

```bash
pip install -r requirements-mcp.txt
```

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "edr-hunt": {
      "command": "python3",
      "args": ["/path/to/opensearch-ui/mcp_hunt_server.py"],
      "env": {
        "OPENSEARCH_URL": "https://your-cluster:9200",
        "OPENSEARCH_INDEX": "ets-telemetry-*",
        "OPENSEARCH_CA_PATH": "/path/to/certs/ca.pem"
      }
    }
  }
}
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_URL` | *(required)* | e.g. `https://cluster:9200` |
| `OPENSEARCH_INDEX` | `_all` | Index pattern to search |
| `OPENSEARCH_TIME_FIELD` | `timestamp` | Field used for first/last seen |
| `OPENSEARCH_CA_PATH` | `""` | CA certificate path (`.pem` or `.pem.enc`) |
| `OPENSEARCH_CERT_PATH` | `""` | Client certificate path |
| `OPENSEARCH_KEY_PATH` | `""` | Client key path |
| `OPENSEARCH_SKIP_HOSTNAME` | `false` | Disable TLS hostname verification |

### Tools

**`hunt_iocs`** — search for a list of IOC values. Auto-detects type per IOC (sha256, sha1, md5, ip, domain, url, registry, process, cmdline, script). Returns a per-IOC summary of matched hosts with event counts and timestamps.

**`get_hunt_events`** — retrieve the actual event documents for an IOC, optionally narrowed to one host by `host_guid`.

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
| `mcp_hunt_server.py` | MCP server for Claude integration |
| `requirements-mcp.txt` | MCP server dependencies |
| `readme.txt` | Plain-text readme |
| `release_notes.txt` | Change history |
| `certs/` | Encrypted certificate storage (auto-created) |
| `certs/.key` | Fernet encryption key — do not share or commit |
| `access.log` | HTTP access log, rotates at 20 MB × 5 files |

---

## License

MIT License — Copyright © 2026
