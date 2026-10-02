"""
EDR Telemetry Hunt — MCP Server

Exposes two tools so Claude can search OpenSearch for IOC values mid-conversation:
  hunt_iocs       – per-IOC host summary (counts, first/last seen)
  get_hunt_events – raw event documents for a matched IOC (optionally one host)

Configuration via environment variables — see _CFG below.
"""
import json
import logging
import os
import re
import ssl
import tempfile
import warnings
from pathlib import Path
from typing import Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter

warnings.filterwarnings("ignore", message=".*OpenSSL.*")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)


# ── Config from env vars ──────────────────────────────────────────────────────

def _require_env(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        raise RuntimeError(
            f"Required environment variable {key!r} is not set. "
            "Configure it in your MCP server settings."
        )
    return val

_CFG = {
    "url":           _require_env("OPENSEARCH_URL").rstrip("/"),
    "index":         os.environ.get("OPENSEARCH_INDEX",      "_all").strip() or "_all",
    "time_field":    os.environ.get("OPENSEARCH_TIME_FIELD", "timestamp").strip() or "timestamp",
    "ca_path":       os.environ.get("OPENSEARCH_CA_PATH",    "").strip(),
    "cert_path":     os.environ.get("OPENSEARCH_CERT_PATH",  "").strip(),
    "key_path":      os.environ.get("OPENSEARCH_KEY_PATH",   "").strip(),
    "skip_hostname": os.environ.get("OPENSEARCH_SKIP_HOSTNAME", "false").lower() in ("1", "true", "yes"),
}


# ── Fernet encryption (for .enc cert files) ───────────────────────────────────

def _load_fernet():
    from cryptography.fernet import Fernet
    key_dir  = Path(__file__).parent / "certs"
    key_dir.mkdir(exist_ok=True)
    key_file = key_dir / ".key"
    if key_file.exists():
        return Fernet(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    key_file.write_bytes(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return Fernet(key)

try:
    _fernet = _load_fernet()
except Exception as _fe:
    log.warning("Fernet unavailable (%s) — certs will be read as plain text", _fe)
    _fernet = None


def _decrypt(path_str):
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


def _request_factory(data):
    cert_path     = data.get("cert_path", "").strip()
    key_path      = data.get("key_path",  "").strip()
    ca_path       = data.get("ca_path",   "").strip()
    skip_hostname = bool(data.get("skip_hostname", False))

    has_enc = any(p and Path(p).suffix == ".enc" for p in (cert_path, key_path, ca_path))

    if skip_hostname or has_enc:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE if skip_hostname else ssl.CERT_REQUIRED

        if ca_path:
            ca_content = _decrypt(ca_path) if has_enc else None
            if ca_content:
                ctx.load_verify_locations(cadata=ca_content)
            elif not has_enc:
                ctx.load_verify_locations(ca_path)

        if cert_path and key_path:
            if has_enc:
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

    kwargs = {}
    if cert_path and key_path:
        kwargs["cert"] = (cert_path, key_path)
    kwargs["verify"] = ca_path if ca_path else False
    return requests, kwargs


# ── IOC normalizers (ported from HUNT_NORMALIZERS in templates/index.html) ────

def _norm_url(v: str) -> str:
    v = re.sub(r"^hxxps?", lambda m: re.sub(r"xx", "tt", m.group(), flags=re.I), v, flags=re.I)
    v = re.sub(r"\[:\/{0,2}\]", lambda m: "://" if "//" in m.group() else ":", v)
    v = re.sub(r"\[\.?\]|\(\.\)", ".", v)
    return v

HUNT_NORMALIZERS = {
    "none":    lambda v: v,
    "process": lambda v: re.sub(r"<[^>]+>", "*", v),
    "ip":      lambda v: re.sub(r"\s", "", re.sub(r"\[\.?\]|\(\.\)|\\\.", ".", v)),
    "domain":  lambda v: re.sub(r"\[\.?\]|\(\.\)", ".", v).lower(),
    "url":     _norm_url,
    "dirpath": lambda v: re.sub(r"[/\\](\*{1,2})?$", "", v),
}


# ── IOC type definitions (ported from _HUNT_TYPES_DEFAULT in templates/index.html) ──

HUNT_TYPES = [
    {
        "id": "sha256", "name": "SHA256 Hash", "normalizer": "none",
        "regexes": [r"\b([a-fA-F0-9]{64})\b"],
        "fields": [
            {"field": "fileAttributes.sha256", "op": "term"},
            {"field": "procFileAttrs.sha256",  "op": "term"},
            {"field": "pSha2",                 "op": "term"},
        ],
    },
    {
        "id": "sha1", "name": "SHA1 Hash", "normalizer": "none",
        "regexes": [r"\b([a-fA-F0-9]{40})\b"],
        "fields": [
            {"field": "fileAttributes.sha1", "op": "term"},
            {"field": "procFileAttrs.sha1",  "op": "term"},
        ],
    },
    {
        "id": "md5", "name": "MD5 Hash", "normalizer": "none",
        "regexes": [r"\b([a-fA-F0-9]{32})\b"],
        "fields": [
            {"field": "fileAttributes.md5", "op": "term"},
            {"field": "procFileAttrs.md5",  "op": "term"},
        ],
    },
    {
        "id": "ip", "name": "IP Address", "normalizer": "ip",
        "regexes": [
            r"\b(\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3}(?:\[\.\]|\(\.\)|\.)\d{1,3})\b",
        ],
        "fields": [
            {"field": "network.srcIp", "op": "term"},
            {"field": "network.dstIp", "op": "term"},
            {"field": "cmdLine",       "op": "match_phrase"},
        ],
    },
    {
        "id": "url", "name": "URL", "normalizer": "url",
        "regexes": [
            r"""(https?://[^\s<>"',]+)""",
            r"""(hxxps?\[://\][^\s<>"',]+)""",
            r"""(hXXps?\[://\][^\s<>"',]+)""",
            r"""(hxxps?://[^\s<>"',]+)""",
            r"""(hXXps?://[^\s<>"',]+)""",
            r"""(https?\[://\][^\s<>"',]+)""",
            r"""(https?\[:\]//[^\s<>"',]+)""",
        ],
        "fields": [
            {"field": "network.layer7.url", "op": "match_phrase"},
            {"field": "cmdLine",            "op": "match_phrase"},
        ],
    },
    {
        "id": "registry", "name": "Registry Key", "normalizer": "none",
        "regexes": [
            r"""((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKCR|HKU|HKEY_USERS|HKCC|HKEY_CURRENT_CONFIG)[\\/][^\s,;'"<>|\n]+)""",
        ],
        "fields": [
            {"field": "registry.keyName",    "op": "match_phrase"},
            {"field": "registry.regKeyName", "op": "match_phrase"},
        ],
    },
    {
        "id": "dns", "name": "DNS / Domain", "normalizer": "domain",
        "regexes": [
            r"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*(?!(?:exe|dll|msi|bat|ps1|vbs|cmd|scr|pif|jar|hta|wsf|lnk|iso|bin|pdf|docx|doc|xlsx|xls|pptx|ppt|txt|log|csv|zip|rar|7z|tar|gz|dat|ini|cfg|tmp|bak|cab|sys|drv|ocx|reg|inf)(?![a-zA-Z0-9\-]))[a-zA-Z]{2,})\b",
            r"\b([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\]|\(\.\))[a-zA-Z0-9\-\.\[\]\(\)]*[a-zA-Z]{2,})\b",
        ],
        "fields": [
            {"field": "network.dnsNames.name", "op": "term"},
            {"field": "dns.name",              "op": "term"},
            {"field": "cmdLine",               "op": "match_phrase"},
        ],
    },
    {
        "id": "process", "name": "Process / File", "normalizer": "process",
        "regexes": [
            r"((?:[A-Za-z]:\\|\\)(?:[^\\:\"|\r\n]+\\)*[^\\:\"|\r\n\s]+\.[A-Za-z0-9]{1,10})",
            r"\b([A-Za-z0-9_\-]+\.(?:exe|dll|msi|bat|ps1|sh|py|vbs|cmd|scr|pif|jar|hta|js|wsf|lnk|iso|bin|pdf|doc|docx|xls|xlsx|ppt|pptx|txt|log|csv|zip|rar|7z|tar|gz|dat|ini|cfg|tmp|bak|cab|sys|drv|ocx|reg|inf))\b",
            r"""(?:^|\s)(?:file(?:name)?|fname)\s*[,: ]+([^\s,;"'<>\r\n]+\.[A-Za-z0-9]{1,10})""",
        ],
        "fields": [
            {"field": "pFullName",           "op": "match_phrase"},
            {"field": "cmdLine",             "op": "match_phrase"},
            {"field": "fileAttributes.path", "op": "match_phrase"},
            {"field": "procFileAttrs.path",  "op": "match_phrase"},
        ],
    },
    {
        "id": "cmdline", "name": "Command Line", "normalizer": "dirpath",
        "regexes": [
            r"((?:[A-Za-z]:\\|(?:\*{1,2})?\\)(?:[^\n\r\"\\]*\\)+(?:\*{1,2})?)",
            r"(/[a-zA-Z0-9_.~\-]+(?:/[a-zA-Z0-9_.~\-]+)+/?(?:\*{1,2})?)",
            r"(/(?:proc|sys|dev|tmp|run|var|usr|home|etc|opt|mnt|srv|lib64?|bin|sbin|boot|root|System|private|Library|Applications?|Users?|Volumes?|Network|snap)\b|/\.[a-zA-Z][a-zA-Z0-9_\-]*|\*/[a-zA-Z.][a-zA-Z0-9_.\-]*)",
        ],
        "fields": [
            {"field": "pFullName",           "op": "match_phrase"},
            {"field": "cmdLine",             "op": "match_phrase"},
            {"field": "fileAttributes.path", "op": "match_phrase"},
            {"field": "procFileAttrs.path",  "op": "match_phrase"},
        ],
    },
    {
        "id": "script", "name": "Script", "normalizer": "none",
        "regexes": [],
        "fields": [
            {"field": "scripts",                  "op": "match_phrase"},
            {"field": "scripts.intentions.name",  "op": "match_phrase"},
            {"field": "scripts.intentions.lines", "op": "match_phrase"},
        ],
    },
    {
        "id": "mutex", "name": "Mutex", "normalizer": "none",
        "regexes": [],
        "fields": [],
    },
]

HUNT_TYPE_BY_ID = {ht["id"]: ht for ht in HUNT_TYPES}


def _detect_ioc_type(value: str, forced_id: Optional[str] = None) -> Optional[dict]:
    if forced_id:
        return HUNT_TYPE_BY_ID.get(forced_id)
    for ht in HUNT_TYPES:
        for pattern in ht["regexes"]:
            if re.search(pattern, value):
                return ht
    return None


def _normalize(value: str, normalizer_key: str) -> str:
    return HUNT_NORMALIZERS.get(normalizer_key, lambda v: v)(value)


# ── OpenSearch query building (ported from _huntFieldClause in templates/index.html) ──

def _field_clause(field_spec: dict, val: str) -> dict:
    f = field_spec["field"]
    if "*" in val:
        segs = [s for s in re.split(r"\*+", val) if s]
        if not segs:
            return {"match_all": {}}
        if len(segs) == 1:
            return {"match_phrase": {f: segs[0]}}
        return {"bool": {"must": [{"match_phrase": {f: s}} for s in segs]}}
    # Linux/macOS paths: match_phrase on keyword fields requires exact full-value match.
    # Use wildcard instead so "/proc" hits "/proc/1234/maps" etc.
    if field_spec["op"] == "match_phrase" and "/" in val and "\\" not in val:
        return {"wildcard": {f: {"value": f"*{val}*"}}}
    op = field_spec["op"]
    if op == "term":            return {"term":    {f: val}}
    if op == "prefix":          return {"prefix":  {f: val}}
    if op == "wildcard_suffix": return {"wildcard": {f: {"value": f"*{val}"}}}
    return {"match_phrase": {f: val}}


def _build_summary_query(norm_val: str, hunt_type: dict, max_results: int) -> dict:
    clauses = [_field_clause(fs, norm_val) for fs in hunt_type["fields"]]
    time_field = _CFG["time_field"]
    return {
        "query": {
            "bool": {
                "filter": [{
                    "bool": {"should": clauses, "minimum_should_match": 1}
                }]
            }
        },
        "aggs": {
            "unique_hosts": {
                "terms": {"field": "maGuid", "size": max_results},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": {"includes": ["host", "maGuid", "systemUniqueID"]},
                        }
                    },
                    "first_seen": {
                        "min": {"field": time_field, "format": "strict_date_optional_time"}
                    },
                    "last_seen": {
                        "max": {"field": time_field, "format": "strict_date_optional_time"}
                    },
                },
            }
        },
        "size": 0,
    }


def _build_detail_query(norm_val: str, hunt_type: dict, host_guid: Optional[str], size: int) -> dict:
    ioc_clauses = [_field_clause(fs, norm_val) for fs in hunt_type["fields"]]
    filters: list = [{"bool": {"should": ioc_clauses, "minimum_should_match": 1}}]
    if host_guid:
        filters.append({"term": {"maGuid": host_guid}})
    return {"query": {"bool": {"filter": filters}}, "size": size}


# ── OpenSearch execution ──────────────────────────────────────────────────────

def _os_search(query_body: dict, index: Optional[str] = None) -> dict:
    http, ssl_kw = _request_factory(_CFG)
    url = f"{_CFG['url']}/{index or _CFG['index']}/_search"
    resp = http.post(
        url, json=query_body, timeout=120,
        headers={"Content-Type": "application/json"},
        **ssl_kw,
    )
    resp.raise_for_status()
    return resp.json()


# ── Result formatting ─────────────────────────────────────────────────────────

def _fmt_ts(ts_str: Optional[str]) -> str:
    if not ts_str:
        return "—"
    return ts_str.replace("T", " ").split(".")[0].split("+")[0]


def _extract_host(sample_hit: dict) -> str:
    src = sample_hit.get("_source", {})
    h = src.get("host", "")
    if isinstance(h, dict):
        return h.get("name") or h.get("hostname") or "(unknown)"
    return str(h) if h else "—"


def _format_ioc_result(ioc_raw: str, norm: str, ht: dict, resp: dict) -> str:
    buckets    = resp.get("aggregations", {}).get("unique_hosts", {}).get("buckets", [])
    total_hits = resp.get("hits", {}).get("total", {}).get("value", 0)
    type_label = ht["name"]

    norm_note = f"  normalized: {norm!r}" if norm != ioc_raw else ""
    header = f"IOC: {ioc_raw!r}  [type: {type_label}{norm_note}]"

    if not buckets:
        return header + "\n  No matches.\n"

    lines = [
        header,
        f"  Matched {len(buckets)} host(s) | {total_hits} total event(s):",
    ]
    for b in buckets:
        hits   = b.get("sample", {}).get("hits", {}).get("hits", [{}])
        host   = _extract_host(hits[0]) if hits else "—"
        guid   = b.get("key", "—")
        events = b.get("doc_count", 0)
        first  = _fmt_ts(b.get("first_seen", {}).get("value_as_string"))
        last   = _fmt_ts(b.get("last_seen",  {}).get("value_as_string"))
        lines.append(
            f"  - {host}  |  maGuid: {guid}  |  Events: {events}  "
            f"|  First: {first}  |  Last: {last}"
        )
    lines.append("")
    return "\n".join(lines)


# ── MCP server ────────────────────────────────────────────────────────────────

mcp = FastMCP("EDR Hunt")


@mcp.tool()
def hunt_iocs(
    iocs: list[str],
    ioc_type: Optional[str] = None,
    max_results: int = 100,
    index: Optional[str] = None,
) -> str:
    """
    Search EDR telemetry for one or more IOC values.

    For each IOC, auto-detects its type (sha256, sha1, md5, ip, url, registry, dns,
    process, cmdline, script), normalizes it, builds an OpenSearch query, and returns
    a per-host summary showing event counts and first/last-seen timestamps.

    Args:
        iocs: List of IOC values extracted from the user's text — hashes, IPs, file
              paths, domains, URLs, registry keys, command-line snippets, etc.
        ioc_type: Force a specific type for ALL IOCs in this call. Valid values:
                  sha256, sha1, md5, ip, url, registry, dns, process, cmdline, script.
                  Omit to auto-detect per IOC (recommended).
        max_results: Maximum number of host buckets returned per IOC (default 100).
        index: Override the configured OPENSEARCH_INDEX for this search.

    Returns:
        Per-IOC block: detected type, matching hosts, event counts, first/last seen.
        Call get_hunt_events() to retrieve the actual event documents for any match.
    """
    idx = index or _CFG["index"]
    out: list[str] = []
    errors: list[str] = []

    for ioc_raw in iocs:
        ioc_raw = ioc_raw.strip()
        if not ioc_raw:
            continue

        ht = _detect_ioc_type(ioc_raw, ioc_type)
        if not ht:
            out.append(
                f"IOC: {ioc_raw!r}  [type: unknown — could not auto-detect; "
                "pass ioc_type to force a type]\n"
            )
            continue
        if not ht["fields"]:
            out.append(f"IOC: {ioc_raw!r}  [type: {ht['name']} — no search fields configured]\n")
            continue

        norm = _normalize(ioc_raw, ht["normalizer"])
        query = _build_summary_query(norm, ht, max_results)
        try:
            resp = _os_search(query, idx)
        except Exception as e:
            errors.append(f"  {ioc_raw!r}: {e}")
            continue

        out.append(_format_ioc_result(ioc_raw, norm, ht, resp))

    result = "\n".join(out)
    if errors:
        result += "\nSearch errors:\n" + "\n".join(errors)
    return result or "No IOCs provided."


@mcp.tool()
def get_hunt_events(
    ioc: str,
    ioc_type: Optional[str] = None,
    host_guid: Optional[str] = None,
    size: int = 20,
    index: Optional[str] = None,
) -> str:
    """
    Retrieve the actual event documents matching an IOC, optionally filtered to one host.

    Call this after hunt_iocs when the user asks to see the underlying events for a match.

    Args:
        ioc: The IOC value to search for (same value passed to hunt_iocs).
        ioc_type: IOC type override. Omit to auto-detect.
        host_guid: maGuid value from hunt_iocs output to restrict results to one host.
                   Omit to return events from all matching hosts.
        size: Number of events to return (default 20, max controlled by OpenSearch).
        index: Override the configured OPENSEARCH_INDEX for this search.

    Returns:
        Matching event _source documents formatted as JSON, with index and document ID.
    """
    ioc = ioc.strip()
    ht = _detect_ioc_type(ioc, ioc_type)
    if not ht:
        return (
            f"Cannot search: IOC type not detected for {ioc!r}. "
            "Specify ioc_type to force a type."
        )
    if not ht["fields"]:
        return f"IOC type {ht['name']!r} has no search fields configured."

    norm  = _normalize(ioc, ht["normalizer"])
    query = _build_detail_query(norm, ht, host_guid, size)
    idx   = index or _CFG["index"]

    try:
        resp = _os_search(query, idx)
    except Exception as e:
        return f"Search error: {e}"

    hits  = resp.get("hits", {}).get("hits", [])
    total = resp.get("hits", {}).get("total", {}).get("value", 0)

    if not hits:
        host_note = f" on host {host_guid!r}" if host_guid else ""
        return f"No events found for {ioc!r}{host_note}."

    host_note = f" on host {host_guid!r}" if host_guid else ""
    lines = [f"Showing {len(hits)} of {total} event(s) for {ioc!r}{host_note}:"]
    for i, hit in enumerate(hits, 1):
        lines.append(
            f"\n--- Event {i}  "
            f"(index: {hit.get('_index', '?')}  id: {hit.get('_id', '?')}) ---"
        )
        lines.append(json.dumps(hit.get("_source", {}), indent=2))
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
