import warnings
warnings.filterwarnings("ignore", message=".*OpenSSL.*")

# ── stdlib imports (safe before any third-party check) ────────────────────────
import json
import logging
import os
import re
import ssl
import tempfile
from importlib.metadata import version as _pkg_version, PackageNotFoundError as _PkgNF
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)
logging.getLogger("waitress").setLevel(logging.ERROR)
logging.getLogger("waitress.queue").setLevel(logging.ERROR)

# ── Requirements check (runs before third-party imports) ─────────────────────
def _check_requirements():
    req_file = Path("requirements.txt")
    if not req_file.exists():
        return
    missing = []
    for line in req_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg = re.split(r"[>=<!;\s\[]", line)[0].strip()
        if not pkg:
            continue
        try:
            _pkg_version(pkg)
        except _PkgNF:
            missing.append(pkg)
    if missing:
        sep = "=" * 62
        log.warning(sep)
        log.warning("MISSING PACKAGES: %s", ", ".join(missing))
        log.warning("Install all requirements:")
        log.warning("  pip install -r requirements.txt")
        log.warning("  python -m pip install -r requirements.txt")
        log.warning("Or install the missing packages only:")
        log.warning("  pip install %s", " ".join(missing))
        log.warning("  python -m pip install %s", " ".join(missing))
        log.warning(sep)

_check_requirements()

# ── Third-party imports ───────────────────────────────────────────────────────
import urllib3
from flask import Flask, g, render_template, request, jsonify
import requests
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "26.09.0.130"


def _load_fernet():
    """Load or create the Fernet encryption key stored in certs/.key (chmod 600)."""
    from cryptography.fernet import Fernet
    key_dir  = Path("certs")
    key_dir.mkdir(exist_ok=True)
    key_file = key_dir / ".key"
    if key_file.exists():
        return Fernet(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass  # Windows doesn't support chmod
    log.info("Generated new cert encryption key at %s", key_file)
    return Fernet(key)

try:
    _fernet = _load_fernet()
except Exception as _fe:
    log.warning("Fernet unavailable (%s) — certs will be stored unencrypted", _fe)
    _fernet = None


def _decrypt(path_str):
    """Return plaintext PEM content from a path (decrypts .enc files, reads plain .pem as-is)."""
    p = Path(path_str)
    if not p.exists():
        return ""
    if p.suffix == ".enc" and _fernet:
        try:
            return _fernet.decrypt(p.read_bytes()).decode()
        except Exception as e:
            log.error("Failed to decrypt %s: %s", p, e)
            return ""
    return p.read_text()


app = Flask(__name__)

# ── Access log — 20 MB × 5 rotating files ────────────────────────────────────
_access_log = logging.getLogger("opensearch_ui.access")
_access_log.setLevel(logging.INFO)
_access_log.propagate = False   # keep access lines out of the main console log
_access_handler = RotatingFileHandler(
    "access.log", maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8",
)
_access_handler.setFormatter(logging.Formatter("%(message)s"))
_access_log.addHandler(_access_handler)


@app.before_request
def _before_request():
    g.req_start = datetime.now(timezone.utc)


@app.after_request
def _log_access(response):
    now      = datetime.now(timezone.utc)
    duration = round((now - g.get("req_start", now)).total_seconds() * 1000)
    ts       = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

    remote_addr = request.remote_addr or "-"
    remote_port = str(request.environ.get("REMOTE_PORT", "-"))

    # Reverse-proxy forwarding headers — critical for troubleshooting access
    # through nginx / HAProxy / AWS ALB / any other load balancer.
    xff        = request.headers.get("X-Forwarded-For",   "-")
    x_real_ip  = request.headers.get("X-Real-IP",         "-")
    x_proto    = request.headers.get("X-Forwarded-Proto",  "-")
    x_host     = request.headers.get("X-Forwarded-Host",   "-")
    x_port     = request.headers.get("X-Forwarded-Port",   "-")
    x_prefix   = request.headers.get("X-Forwarded-Prefix", "-")
    host_hdr   = request.headers.get("Host", "-")

    path = request.path
    if request.query_string:
        path += "?" + request.query_string.decode("utf-8", "replace")
    proto    = request.environ.get("SERVER_PROTOCOL", "HTTP/1.1")
    size_str = str(response.content_length) if response.content_length is not None else "-"
    ua       = request.headers.get("User-Agent", "-")
    referer  = request.headers.get("Referer", "-")

    _access_log.info(
        '%s %s:%s "%s %s %s" %s %s %dms'
        ' XFF="%s" X-Real-IP="%s" X-Proto="%s" X-Host="%s" X-Port="%s" X-Prefix="%s"'
        ' Host="%s" UA="%s" Ref="%s"',
        ts,
        remote_addr, remote_port,
        request.method, path, proto,
        response.status_code, size_str, duration,
        xff, x_real_ip, x_proto, x_host, x_port, x_prefix,
        host_hdr, ua, referer,
    )
    return response


def _request_factory(data):
    """Return (http_client, request_kwargs) configured for mTLS.

    Transparently decrypts .enc files written by save_certs(). When skip_hostname
    is True, IP/hostname validation is fully bypassed (CERT_NONE). When encrypted
    certs are present but skip_hostname is False, cert chain validation is kept.
    """
    cert_path     = data.get("cert_path", "").strip()
    key_path      = data.get("key_path",  "").strip()
    ca_path       = data.get("ca_path",   "").strip()
    skip_hostname = bool(data.get("skip_hostname", False))

    has_enc = any(p and Path(p).suffix == ".enc" for p in (cert_path, key_path, ca_path))

    if skip_hostname or has_enc:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        # skip_hostname → trust nothing; encrypted-only → still verify the chain
        ctx.verify_mode = ssl.CERT_NONE if skip_hostname else ssl.CERT_REQUIRED

        if ca_path:
            ca_content = _decrypt(ca_path) if has_enc else None
            if ca_content:
                ctx.load_verify_locations(cadata=ca_content)
            elif not has_enc:
                ctx.load_verify_locations(ca_path)

        if cert_path and key_path:
            if has_enc:
                # Decrypt to short-lived temp files; load_cert_chain reads them
                # immediately so they can be deleted before the request is made.
                tmp_cert = tmp_key = None
                cert_content = _decrypt(cert_path)
                key_content  = _decrypt(key_path)
                if not cert_content or not key_content:
                    log.error("Client cert/key decryption failed — re-save certificates in Settings")
                else:
                    try:
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                            f.write(cert_content); tmp_cert = f.name
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
                            f.write(key_content); tmp_key = f.name
                        ctx.load_cert_chain(tmp_cert, tmp_key)
                    finally:
                        for t in (tmp_cert, tmp_key):
                            if t:
                                try: os.unlink(t)
                                except OSError: pass
            else:
                ctx.load_cert_chain(cert_path, key_path)

        class _Adapter(HTTPAdapter):
            def init_poolmanager(self, *a, **kw):
                kw.update(ssl_context=ctx, assert_hostname=False)
                super().init_poolmanager(*a, **kw)

        session = requests.Session()
        session.mount("https://", _Adapter())
        return session, {}

    # Standard path — plain .pem files, full hostname + cert verification
    kwargs = {}
    if cert_path and key_path:
        kwargs["cert"] = (cert_path, key_path)
    kwargs["verify"] = ca_path if ca_path else False
    return requests, kwargs


def _find_local_certs():
    """Return cert/key/ca paths if .pem files exist in the launch directory."""
    pem_files = sorted(Path(".").glob("*.pem"))
    if not pem_files:
        return None
    cert_path = key_path = ca_path = ""
    for p in pem_files:
        n = p.name.lower()
        abs_path = str(p.resolve())
        if n.endswith("-key.pem") or "-key" in n:
            key_path = abs_path
        elif n in ("ca.pem", "root-ca.pem") or n.startswith("ca") or "root-ca" in n:
            ca_path = abs_path
        else:
            if not cert_path:
                cert_path = abs_path
    return {"cert_path": cert_path, "key_path": key_path, "ca_path": ca_path}


@app.route("/")
def index():
    return render_template("index.html", version=VERSION, local_certs=_find_local_certs())


@app.route("/api/ping")
def ping():
    return jsonify({"ok": True, "version": VERSION})


@app.route("/api/connect", methods=["POST"])
def connect():
    data = request.json
    base_url = data.get("url", "").rstrip("/")
    http, ssl_kw = _request_factory(data)

    try:
        # Cluster info — optional; some accounts lack cluster:monitor/main permission
        cluster_name = "unknown"
        cluster_ver  = "unknown"
        try:
            info = http.get(f"{base_url}/", timeout=10, **ssl_kw)
            if info.status_code != 403:
                info.raise_for_status()
                c = info.json()
                cluster_name = c.get("cluster_name", "unknown")
                cluster_ver  = c.get("version", {}).get("number", "unknown")
        except requests.exceptions.HTTPError:
            pass  # limited-permission account; proceed anyway

        # Index listing — optional; fall back to empty list if not permitted
        indices = []
        try:
            indices_resp = http.get(
                f"{base_url}/_cat/indices?format=json&s=index&h=index,docs.count,store.size",
                timeout=10,
                **ssl_kw,
            )
            if indices_resp.status_code != 403:
                indices_resp.raise_for_status()
                indices = [
                    i["index"]
                    for i in indices_resp.json()
                    if not i["index"].startswith(".")
                ]
        except requests.exceptions.HTTPError:
            pass  # no list-indices permission; user can type index name manually

        return jsonify(
            {
                "success": True,
                "cluster_name": cluster_name,
                "version": cluster_ver,
                "indices": indices,
            }
        )
    except requests.exceptions.SSLError as e:
        msg = str(e)
        if "IP address mismatch" in msg or "hostname mismatch" in msg or "CERTIFICATE_VERIFY_FAILED" in msg:
            msg += " — try enabling 'Skip hostname verification' in the server settings"
        return jsonify({"success": False, "error": f"SSL error: {msg}"}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": f"Cannot connect to {base_url}"}), 400
    except requests.exceptions.HTTPError as e:
        return jsonify({"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/search", methods=["POST"])
def search():
    data = request.json
    base_url = data.get("url", "").rstrip("/")
    index = data.get("index", "_all")
    query_body = data.get("query", {"query": {"match_all": {}}})
    size = int(data.get("size", 10))
    from_val = int(data.get("from", 0))
    http, ssl_kw = _request_factory(data)

    query_body = {**query_body, "size": size, "from": from_val}

    try:
        resp = http.post(
            f"{base_url}/{index}/_search",
            json=query_body,
            timeout=120,
            headers={"Content-Type": "application/json"},
            **ssl_kw,
        )
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.SSLError as e:
        return jsonify({"error": f"SSL error: {e}"}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot connect to {base_url}"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route("/api/save_certs", methods=["POST"])
def save_certs():
    data        = request.json
    server_name = re.sub(r"[^\w\-]", "_", data.get("server_name", "server"))
    cert_dir    = Path("certs") / server_name
    cert_dir.mkdir(parents=True, exist_ok=True)

    result = {"success": True}
    for key, fname, out_key in [
        ("ca_content",   "ca.pem",        "ca_path"),
        ("cert_content", "client.pem",     "cert_path"),
        ("key_content",  "client-key.pem", "key_path"),
    ]:
        content = (data.get(key) or "").strip()
        if content:
            raw = (content + "\n").encode()
            if _fernet:
                p = cert_dir / (fname + ".enc")
                p.write_bytes(_fernet.encrypt(raw))
            else:
                p = cert_dir / fname
                p.write_text(content + "\n")
            result[out_key] = str(p.resolve())
            log.info("Saved cert to %s", p)

    return jsonify(result)


_CORE_SETTINGS   = Path("ets_explorer_core_setting.json")
_CUSTOM_SETTINGS = Path("ets_explorer_custom.json")


@app.route("/api/settings/core", methods=["GET"])
def get_core_settings():
    if _CORE_SETTINGS.exists():
        return jsonify(json.loads(_CORE_SETTINGS.read_text(encoding="utf-8")))
    return jsonify({})


@app.route("/api/settings/core", methods=["POST"])
def save_core_settings():
    _CORE_SETTINGS.write_text(json.dumps(request.json, indent=2, ensure_ascii=False), encoding="utf-8")
    return jsonify({"success": True})


@app.route("/api/settings/custom", methods=["GET"])
def get_custom_settings():
    if _CUSTOM_SETTINGS.exists():
        return jsonify(json.loads(_CUSTOM_SETTINGS.read_text(encoding="utf-8")))
    return jsonify({})


@app.route("/api/settings/custom", methods=["POST"])
def save_custom_settings():
    _CUSTOM_SETTINGS.write_text(json.dumps(request.json, indent=2, ensure_ascii=False), encoding="utf-8")
    return jsonify({"success": True})


@app.route("/api/openioc/tree")
def openioc_tree():
    root = Path("OpenIOC")
    if not root.exists():
        return jsonify({"error": "OpenIOC directory not found"}), 404

    def walk(p):
        if p.is_file():
            return {"type": "file", "name": p.stem, "path": p.relative_to(root).as_posix()}
        children = sorted(
            [walk(c) for c in p.iterdir() if c.suffix == ".ioc" or c.is_dir()],
            key=lambda x: (x["type"] == "file", x["name"])
        )
        count = sum(1 for _ in p.rglob("*.ioc"))
        return {"type": "dir", "name": p.name, "children": children, "count": count}

    return jsonify(walk(root))


@app.route("/api/openioc/read", methods=["POST"])
def openioc_read():
    root = Path("OpenIOC").resolve()
    paths = request.json.get("paths", [])
    results = []
    for rel in paths:
        p = (root / rel).resolve()
        if not str(p).startswith(str(root) + os.sep) and str(p) != str(root):
            continue  # path traversal guard
        if p.exists() and p.suffix == ".ioc":
            results.append({"path": rel, "xml": p.read_text(encoding="utf-8")})
    return jsonify({"files": results})


@app.route("/api/openioc/list")
def openioc_list():
    import xml.etree.ElementTree as ET
    root = Path("OpenIOC")
    if not root.exists():
        return jsonify({"error": "OpenIOC directory not found"}), 404
    NS = "http://openioc.org/schemas/OpenIOC_1.1"
    result = []
    for p in sorted(root.rglob("*.ioc")):
        rel = p.relative_to(root).as_posix()
        folder = Path(rel).parent.as_posix()
        entry = {"path": rel, "name": p.stem, "folder": folder, "modified": "", "authored": "", "author": "", "desc": p.stem}
        try:
            t = ET.parse(p)
            r = t.getroot()
            entry["modified"] = r.get("last-modified", "")
            authored = r.find(f".//{{{NS}}}authored_date")
            if authored is not None:
                entry["authored"] = (authored.text or "").strip()
            author = r.find(f".//{{{NS}}}authored_by")
            if author is not None and author.text:
                entry["author"] = author.text.strip()
            desc = r.find(f".//{{{NS}}}short_description")
            if desc is not None and desc.text:
                entry["desc"] = desc.text.strip()
        except Exception:
            pass
        result.append(entry)
    return jsonify({"files": result})


if __name__ == "__main__":
    from waitress import serve
    host, port = "0.0.0.0", 5001
    log.info("OpenSearch UI v%s  →  http://%s:%d", VERSION, host, port)
    try:
        serve(app, host=host, port=port, threads=32)
    except OSError as e:
        if e.errno == 48 or "Address already in use" in str(e):
            sep = "=" * 62
            log.error(sep)
            log.error("Port %d is already in use.", port)
            log.error("Another process (or a previous instance of this app)")
            log.error("is already listening on that port.")
            log.error("")
            log.error("To use a different port, edit app.py and change:")
            log.error("    host, port = \"%s\", %d", host, port)
            log.error("For example, to use port 5002:")
            log.error("    host, port = \"0.0.0.0\", 5002")
            log.error(sep)
        else:
            raise
