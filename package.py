#!/usr/bin/env python3
"""Create a distributable zip of the OpenSearch UI app."""
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent

# Read version from app.py
m = re.search(r'^VERSION = "(\S+)"', (ROOT / "app.py").read_text(), re.MULTILINE)
if not m:
    print("ERROR: Could not read VERSION from app.py"); sys.exit(1)
version = m.group(1)

INCLUDE = [
    "app.py",
    "requirements.txt",
    "readme.txt",
    "release_notes.txt",
    "templates/index.html",
    "static/css/bootstrap.min.css",
    "static/css/github-dark.min.css",
    "static/js/bootstrap.bundle.min.js",
    "static/js/highlight.min.js",
    "static/js/highlight-powershell.min.js",
]

out_name = f"EDR_Telemetry_Store_Explorer_{version}.zip"
out_path = ROOT / out_name

missing = [f for f in INCLUDE if not (ROOT / f).exists()]
if missing:
    print("ERROR: Missing files:"); [print(f"  {f}") for f in missing]; sys.exit(1)

with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
    for rel in INCLUDE:
        zf.write(ROOT / rel, rel)
        print(f"  added  {rel}")

size_kb = out_path.stat().st_size // 1024
print(f"\nCreated {out_name}  ({size_kb} KB)")
