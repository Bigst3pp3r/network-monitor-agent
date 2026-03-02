#!/usr/bin/env python3
"""
build_oui_db.py — Seeds the OUI SQLite database from the nmap mac-prefixes file.

Run this ONCE on your Linux host (not inside Docker):

    python3 scripts/build_oui_db.py

It reads /usr/share/nmap/nmap-mac-prefixes, parses every prefix→vendor
entry, and writes them into data/oui.db (SQLite).

The database is then mounted into the Docker container and used by oui.py
for instant offline vendor lookups.

You can re-run this any time to refresh the database after an nmap update.
"""

import sqlite3
import os
import sys
import re
import time

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR     = os.path.join(PROJECT_ROOT, "data")
OUI_DB_PATH  = os.path.join(DATA_DIR, "oui.db")

# nmap ships this file on Ubuntu/Debian — already on your machine
NMAP_PREFIXES = "/usr/share/nmap/nmap-mac-prefixes"

# Fallback: also accept an IEEE oui.txt if the user has downloaded one
IEEE_OUI_TXT  = os.path.join(PROJECT_ROOT, "oui.txt")


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_nmap_prefixes(path: str) -> list[tuple[str, str]]:
    """
    Parse /usr/share/nmap/nmap-mac-prefixes.

    Format:
        000000 Officially Xerox
        0000E8 Accton Technology Corporation
        ...
    Each line: 6 hex digits, space, vendor name. No headers.
    """
    entries: list[tuple[str, str]] = []
    pattern = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+)$")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = pattern.match(line)
            if m:
                prefix = m.group(1).upper()
                vendor = m.group(2).strip()
                entries.append((prefix, vendor))

    return entries


def parse_ieee_oui_txt(path: str) -> list[tuple[str, str]]:
    """
    Parse the IEEE oui.txt bulk file.

    Relevant lines look like:
        00-00-00   (hex)        Xerox Corporation
        000000     (base 16)    Xerox Corporation
    We use the (base 16) lines as they're cleaner.
    """
    entries: list[tuple[str, str]] = []
    pattern = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                prefix = m.group(1).upper()
                vendor = m.group(2).strip()
                entries.append((prefix, vendor))

    return entries


def parse_wireshark_manuf(path: str) -> list[tuple[str, str]]:
    """
    Parse a Wireshark manuf file (tab-separated).

    Format:
        00:00:00\tXerox\tXerox Corporation
    We take the last (long) name column when available.
    """
    entries: list[tuple[str, str]] = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            mac_raw = parts[0].replace(":", "").replace("-", "")
            if len(mac_raw) != 6:
                continue
            # Use long name (col 3) if available, else short name (col 2)
            vendor = parts[2].strip() if len(parts) >= 3 else parts[1].strip()
            entries.append((mac_raw.upper(), vendor))

    return entries


# ── Database builder ──────────────────────────────────────────────────────────

def build_database(entries: list[tuple[str, str]], source: str):
    """Write all entries into a fresh SQLite OUI database."""
    os.makedirs(DATA_DIR, exist_ok=True)

    # Remove old db so we start clean
    if os.path.exists(OUI_DB_PATH):
        os.remove(OUI_DB_PATH)
        print(f"  Removed existing database at {OUI_DB_PATH}")

    conn = sqlite3.connect(OUI_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.execute("""
        CREATE TABLE oui (
            prefix  TEXT PRIMARY KEY,   -- 6 uppercase hex chars e.g. 'A4C361'
            vendor  TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE meta (
            key     TEXT PRIMARY KEY,
            value   TEXT
        )
    """)

    # Bulk insert
    conn.executemany(
        "INSERT OR REPLACE INTO oui (prefix, vendor) VALUES (?, ?)",
        entries
    )

    # Store metadata
    conn.execute("INSERT INTO meta VALUES ('source', ?)",      (source,))
    conn.execute("INSERT INTO meta VALUES ('entry_count', ?)", (str(len(entries)),))
    conn.execute("INSERT INTO meta VALUES ('built_at', ?)",    (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),))

    conn.commit()

    # Verify
    count = conn.execute("SELECT COUNT(*) FROM oui").fetchone()[0]
    conn.close()

    return count


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  OUI Database Builder")
    print("=" * 60)

    entries: list[tuple[str, str]] = []
    source = ""

    # Try sources in order of preference
    if os.path.exists(NMAP_PREFIXES):
        print(f"\n[1/3] Found nmap mac-prefixes at {NMAP_PREFIXES}")
        print("      Parsing...")
        entries = parse_nmap_prefixes(NMAP_PREFIXES)
        source = f"nmap:{NMAP_PREFIXES}"

    elif os.path.exists(IEEE_OUI_TXT):
        print(f"\n[1/3] Found IEEE oui.txt at {IEEE_OUI_TXT}")
        print("      Parsing...")
        entries = parse_ieee_oui_txt(IEEE_OUI_TXT)
        source = f"ieee:{IEEE_OUI_TXT}"

    else:
        print("\n[1/3] No source file found.")
        print(f"      Looked for: {NMAP_PREFIXES}")
        print(f"      Looked for: {IEEE_OUI_TXT}")
        print()
        print("  To fix, run ONE of these on your Linux host:")
        print()
        print("  Option A — use nmap (recommended, already installed):")
        print("    sudo apt install nmap")
        print()
        print("  Option B — download IEEE file manually:")
        print("    curl -A 'Mozilla/5.0' https://standards-oui.ieee.org/oui/oui.txt -o oui.txt")
        print("    (move oui.txt into the project root folder)")
        print()
        sys.exit(1)

    if not entries:
        print("  ERROR: Parsed 0 entries. File may be empty or in unexpected format.")
        sys.exit(1)

    print(f"      Parsed {len(entries):,} vendor entries")

    # Build the database
    print(f"\n[2/3] Building SQLite database at {OUI_DB_PATH}...")
    count = build_database(entries, source)
    print(f"      Written {count:,} entries")

    # Quick sanity check
    print("\n[3/3] Sanity check — sample lookups:")
    conn = sqlite3.connect(OUI_DB_PATH)
    samples = [
        ("B827EB", "Raspberry Pi Foundation"),
        ("CC2D21", "Tenda"),
        ("A4C361", "Apple"),
    ]
    for prefix, expected in samples:
        row = conn.execute(
            "SELECT vendor FROM oui WHERE prefix=?", (prefix,)
        ).fetchone()
        result = row[0] if row else "NOT FOUND"
        status = "✓" if row else "—"
        print(f"      {status}  {prefix} → {result}")
    conn.close()

    print()
    print("=" * 60)
    print(f"  SUCCESS — oui.db built with {count:,} entries")
    print(f"  Location: {OUI_DB_PATH}")
    print()
    print("  Next: rebuild your Docker container to pick up the new database")
    print("    docker compose down && docker compose build && docker compose up -d")
    print("=" * 60)


if __name__ == "__main__":
    main()
