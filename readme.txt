EDR Telemetry Store Explorer
=============================

A browser-based search and investigation tool for OpenSearch clusters.
Designed for querying and analyzing EDR telemetry stored in OpenSearch.

Current version: 26.08.0.125


Requirements
------------
Python 3.10 or newer.


Installation
------------
1. Install dependencies:

       pip install -r requirements.txt

   This installs:
     - flask        — web framework
     - requests     — HTTP client for OpenSearch API calls
     - waitress     — production WSGI server
     - cryptography — Fernet encryption for certificates stored at rest


Running
-------
    python app.py

The app starts on http://0.0.0.0:5001
Open http://localhost:5001 in your browser.


Connecting to OpenSearch
------------------------
1. Open the Connection Settings panel (gear icon or Settings tab).
2. Enter the server name and OpenSearch URL (e.g. https://host:9200).
3. Add the certificate (see TLS section below).
4. Click Connect.

On a successful connection the cluster name, version, and available indices
are displayed. If the index list is not available due to permissions, type the
index name or pattern manually.


TLS / mTLS (optional)
----------------------
If your OpenSearch cluster requires client certificates, there are two ways to
provide them:

(A) Paste All Certificates (recommended)
    Paste the full output of the appliance command:
        show certificates hxclient
    The CA certificate, client certificate, and private key are detected
    automatically. Click Save — the certificates are encrypted with Fernet
    (AES-128-CBC + HMAC-SHA256) and stored as .enc files under certs/<server-name>/.
    Decryption happens in memory only during the TLS handshake; no plaintext is
    written to disk.

(B) Individual .pem file paths
    Expand the "Individual file paths" section and enter the full paths to:
      - CA certificate     (e.g. C:\certs\ca.pem)
      - Client certificate (e.g. C:\certs\client.pem)
      - Client key         (e.g. C:\certs\client-key.pem)

Alternatively, place .pem files in the same directory as app.py. The app will
detect and pre-fill them automatically at startup using these naming conventions:
  - Client cert : anything not matching key/CA patterns
  - Client key  : filename contains "-key"
  - CA cert     : filename is ca.pem, root-ca.pem, or starts with "ca"

"Skip hostname verification": enable this if the server certificate does not
match the hostname or IP address used to connect (e.g. self-signed certs).

Note: if you install a new version in a different directory, the Fernet
encryption key is regenerated. Re-save your certificates through the UI
to re-encrypt them with the new key.


Server Groups
-------------
Multiple servers can be grouped and queried simultaneously. Results from all
servers in the group are merged and displayed together. Create and manage groups
in the Settings panel under the Server Groups column.


Features
--------
Search
  Build queries with field-value filters or raw DSL JSON. Results are shown as
  collapsible event cards (Results tab) or a sortable, filterable table (Table tab).

Table view
  Click any row to open a full event-detail panel on the right. Right-click any
  cell or detail field to add include/exclude filters, jump to the Story Graph,
  add the field to a custom column set, or add it to a Group By aggregation.

Column sets
  Switch between predefined column sets (Process, Network, File, DNS, Registry,
  ScheduleTask, Script) or build your own in the Settings tab. Each column set
  comes with predefined filter templates that load automatically when switched.

Group By
  Aggregate events by one or more fields. Right-click any cell and choose
  "Add to Group By", or type field names manually. Results show event count,
  unique host count, and first / last seen timestamps per bucket. Left-click a
  bucket row to apply it as a filter; right-click to include or exclude.

Hunt
  Paste a block of threat-intelligence text (file paths, hashes, domains, IPs,
  registry keys, mutexes, URLs) or structured CSV (Indicator_type,Data,Note) and
  run it as a single search. Step 1 produces an Affected Hosts table (host,
  maGuid, systemUniqueID, event count, first seen, last seen); Step 2 loads the
  matching event cards on demand. Right-click any cell in the Affected Hosts table
  to filter; right-click First/Last Seen to add a time >= / <= filter. Hunts can
  be saved and reloaded.

OpenIOC
  Run FireEye/Trellix .ioc files against the EDR Telemetry cluster. Browse the
  local OpenIOC/ directory in a file tree organized by MITRE ATT&CK tactic, OS,
  and confidence level. Select individual files or whole folders and run them as
  a single search. Step 1 shows an Affected Hosts table (host, maGuid,
  systemUniqueID, event count, first/last seen); Step 2 loads matching event
  cards labeled with the IOC file name that matched.

Story Graph
  Renders the parent-child trace chain of an event as a directed graph, useful
  for following attack chains through EDR telemetry.

Query optimisation
  Analyses the active query and suggests index mappings, composite aggregations,
  and date-histogram rollups to improve search performance.

Code generation
  The Python and PowerShell tabs emit ready-to-run SDK snippets that reproduce
  the current search exactly.

Live tail
  Polls for new events using a high-watermark with client-side _id deduplication.
  Table sorts by Time descending automatically while tail is active.

Dark / light mode
  Toggle with the sun/moon button in the top bar; preference is persisted.


Files
-----
  app.py                        — Flask/Waitress application (start here)
  requirements.txt              — Python dependencies
  templates/index.html          — Single-page HTML/JS frontend
  static/                       — CSS and JS libraries
  readme.txt                    — This file
  release_notes.txt             — Change history
  ets_explorer_core_setting.json — Hunt types, column sets, predefined filters
  ets_explorer_custom.json       — Server groups, custom column sets, saved hunts
  certs/                        — Encrypted certificate storage (auto-created)
  certs/.key                    — Fernet encryption key (auto-generated, do not share)
  access.log                    — HTTP access log (auto-created, rotates at 20 MB)
