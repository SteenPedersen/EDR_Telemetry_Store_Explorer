EDR Telemetry Store Explorer
=============================

A browser-based search and investigation tool for OpenSearch clusters.
Designed for querying and analyzing EDR telemetry stored in OpenSearch.

Current version: 26.06.0.107


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


Files
-----
  app.py            — Flask/Waitress application (start here)
  requirements.txt  — Python dependencies
  templates/        — Single-page HTML/JS frontend (index.html)
  static/           — CSS and JS libraries
  readme.txt        — This file
  release_notes.txt — Change history
  certs/            — Encrypted certificate storage (auto-created on first save)
  certs/.key        — Fernet encryption key (auto-generated, do not share)
