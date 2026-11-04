#!/usr/bin/env python3
"""
forensic_agent.py - Automated verification agent for the Android 11 (Pixel 3) image.

It repeats, automatically and in order, the manual steps of the project:
  1. Integrity     : hash Data.tar (MD5, SHA-1, SHA-256) and compare with image_info.txt
  2. Extraction    : copy the target SQLite databases out of the tar (one single pass,
                     the hash is computed during the same read)
  3. Preservation  : hash the extracted copies, make them read-only, create working copies
  4. SQL analysis  : SMS/MMS counts, deleted-row traces (sqlite_sequence), WhatsApp
                     message types and locations, accounts
  5. Comparison    : compare the results with ALEAPP's TSV exports
  6. Re-verification: re-hash the extracted copies, compare working copies
  7. Reporting     : agent_log.txt (every action, timestamped), results.json, report.html

Only the Python standard library is used. The evidence is opened read-only and never modified.

Usage (Windows PowerShell):
  python forensic_agent.py
  python forensic_agent.py --tar "D:\\Evidence\\Data.tar" --out "C:\\Enquete\\Agent"
  python forensic_agent.py --help
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile

VERSION = "1.1"

# ---------------------------------------------------------------- default paths
BASE = r"D:\Enquete_Android11\02_Travail\Android 11\Android 11 Image with Documentation"
DEFAULT_TAR = BASE + r"\Extraction\Android 11 - Pixel 3 - Data.tar"
DEFAULT_IMAGE_INFO = BASE + r"\Extraction Info\image_info.txt"
DEFAULT_ALEAPP_TSV = r"D:\Enquete_Android11\03_Rapports\ALEAPP_Output_2026-10-19_Monday_134141\_TSV Exports"
DEFAULT_OUT = r"C:\Enquete\Agent"

# Reference values from the 2020 acquisition record (used if image_info.txt cannot be read)
REF_MD5 = "aca33f3de4e228c29bc39576865fe7d9"
REF_SHA1 = "a7a4b184946af72c97395462816931c453f073c4"

# Files to extract from the tar (paths inside the image)
TARGETS = [
    "data/data/com.android.providers.telephony/databases/mmssms.db",
    "data/data/com.android.providers.telephony/databases/mmssms.db-journal",
    "data/user_de/0/com.android.providers.telephony/databases/mmssms.db",
    "data/user_de/0/com.android.providers.telephony/databases/mmssms.db-journal",
    "data/data/com.whatsapp/databases/msgstore.db",
    "data/data/com.whatsapp/databases/msgstore.db-wal",
    "data/data/com.whatsapp/databases/msgstore.db-shm",
    "data/system_ce/0/accounts_ce.db",
]
# Files whose presence is only reported (not extracted)
PRESENCE_CHECKS = {
    "WhatsApp encryption key": "data/data/com.whatsapp/files/key",
    "WhatsApp encrypted backup": "data/media/0/WhatsApp/Databases/msgstore.db.crypt12",
}

MMS_ACTIVE = "data/data/com.android.providers.telephony/databases/mmssms.db"
MMS_DE = "data/user_de/0/com.android.providers.telephony/databases/mmssms.db"
WA_DB = "data/data/com.whatsapp/databases/msgstore.db"
ACC_DB = "data/system_ce/0/accounts_ce.db"


# ---------------------------------------------------------------- logging
class Log:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")

    def __call__(self, msg, level="INFO"):
        line = "%s  %-5s  %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, msg)
        print(line)
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


# ---------------------------------------------------------------- helpers
class HashingReader:
    """File wrapper that hashes every byte read (so tar extraction and hashing share one pass)."""

    def __init__(self, f, total, log):
        self.f, self.total, self.log = f, total, log
        self.md5, self.sha1, self.sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        self.done = 0
        self.next_report = 0

    def read(self, n=-1):
        b = self.f.read(n)
        if b:
            self.md5.update(b)
            self.sha1.update(b)
            self.sha256.update(b)
            self.done += len(b)
            if self.done >= self.next_report:
                pct = 100.0 * self.done / self.total if self.total else 0
                print("      ... %6.1f %%  (%.2f GB read)" % (pct, self.done / 1e9), flush=True)
                self.next_report += 1_000_000_000
        return b

    def drain(self):
        while self.read(8 * 1024 * 1024):
            pass

    def digests(self):
        return {"md5": self.md5.hexdigest(), "sha1": self.sha1.hexdigest(), "sha256": self.sha256.hexdigest()}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_image_info(path, log):
    ref = {"md5": REF_MD5, "sha1": REF_SHA1, "source": "built-in reference values"}
    if not path or not os.path.isfile(path):
        log("image_info.txt not found at %s - using built-in reference values" % path, "WARN")
        return ref
    text = open(path, encoding="utf-8", errors="ignore").read()
    # image_info.txt lists several hashes (the image segment AND log files such as activity_log.txt),
    # so every MD5 / SHA-1 value found is kept as a candidate, with its line for the report.
    md5s, sha1s = [], []
    for line in text.splitlines():
        u = line.upper()
        if "MD5" in u:
            md5s += [(h.lower(), line.strip()) for h in re.findall(r"\b([0-9A-Fa-f]{32})\b", line)]
        if re.search(r"SHA-?1\b", u):
            sha1s += [(h.lower(), line.strip()) for h in re.findall(r"\b([0-9A-Fa-f]{40})\b", line)]
    if md5s:
        ref["md5_candidates"] = md5s
    if sha1s:
        ref["sha1_candidates"] = sha1s
    md5, sha1 = bool(md5s), bool(sha1s)
    ref["source"] = path if (md5 or sha1) else "built-in reference values (no hash found in file)"
    return ref


def safe_join(root, member_name):
    parts = [p for p in member_name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(root, *parts)


def make_readonly(path):
    os.chmod(path, stat.S_IREAD)


def make_writable(path):
    os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def connect_ro(path):
    uri = "file:" + path.replace("\\", "/") + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True)
        con.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return con
    except sqlite3.Error:
        return sqlite3.connect(path)  # working copy: safe fallback


def tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def columns(con, table):
    return {r[1] for r in con.execute("PRAGMA table_info(%s)" % table)}


def one(con, sql):
    try:
        r = con.execute(sql).fetchone()
        return r[0] if r else None
    except sqlite3.Error as e:
        return "error: %s" % e


def utc(ms, seconds=False):
    try:
        v = int(ms) if seconds else int(ms) / 1000.0
        return dt.datetime.fromtimestamp(v, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def local(ms, seconds=False, offset_h=-4):
    try:
        v = int(ms) if seconds else int(ms) / 1000.0
        return (dt.datetime.fromtimestamp(v, dt.timezone.utc) + dt.timedelta(hours=offset_h)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def read_tsv(path):
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f, delimiter="\t"))
    return rows[0], rows[1:]


# ---------------------------------------------------------------- steps
def step_extract_and_hash(tar_path, extracted_dir, log, results):
    log("STEP 1+2 - Hash Data.tar and extract target databases (single read of the evidence)")
    if not os.path.isfile(tar_path):
        log("Evidence not found: %s" % tar_path, "ERROR")
        raise SystemExit(1)
    size = os.path.getsize(tar_path)
    log("Evidence: %s (%s bytes) - opened read-only" % (tar_path, format(size, ",")))
    found, presence = {}, {k: False for k in PRESENCE_CHECKS}
    wanted = set(TARGETS)
    with open(tar_path, "rb") as raw:
        reader = HashingReader(raw, size, log)
        with tarfile.open(fileobj=reader, mode="r|") as tf:
            for m in tf:
                name = m.name.lstrip("./")
                for label, p in PRESENCE_CHECKS.items():
                    if name == p:
                        presence[label] = True
                if name in wanted and m.isfile():
                    dest = safe_join(extracted_dir, name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    src = tf.extractfile(m)
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
                    found[name] = {"size": m.size, "mtime_utc": utc(m.mtime, seconds=True)}
                    log("Extracted %s (%s bytes)" % (name, format(m.size, ",")))
        reader.drain()
    digests = reader.digests()
    results["tar"] = {"path": tar_path, "size": size, **digests}
    results["extracted"] = found
    results["presence"] = presence
    missing = sorted(wanted - set(found))
    for mname in missing:
        log("Not present in the image: %s" % mname, "WARN")
    for label, ok in presence.items():
        log("%s: %s" % (label, "present" if ok else "absent"))
    log("MD5    %s" % digests["md5"])
    log("SHA-1  %s" % digests["sha1"])
    log("SHA-256 %s" % digests["sha256"])
    return digests


def step_integrity(digests, ref, log, results):
    log("STEP 1b - Compare with the acquisition record (%s)" % ref["source"])
    def check(alg):
        cands = ref.get(alg + "_candidates") or [(ref[alg], "built-in reference value")]
        for h, line in cands:
            if h == digests[alg]:
                ref[alg] = h
                log("%s found in the record on the line: %s" % (alg.upper(), line))
                return True
        ref[alg] = cands[0][0]
        return False
    md5_ok = check("md5")
    sha1_ok = check("sha1")
    results["integrity"] = {"reference": ref, "md5_match": md5_ok, "sha1_match": sha1_ok}
    log("MD5   %s" % ("MATCH" if md5_ok else "MISMATCH"), "INFO" if md5_ok else "ERROR")
    log("SHA-1 %s" % ("MATCH" if sha1_ok else "MISMATCH"), "INFO" if sha1_ok else "ERROR")
    if not (md5_ok and sha1_ok):
        log("The evidence does NOT match the acquisition record. Results below must not be trusted.", "ERROR")


def hash_tree(root):
    out = {}
    for d, _, files in os.walk(root):
        for fn in sorted(files):
            p = os.path.join(d, fn)
            out[os.path.relpath(p, root).replace("\\", "/")] = sha256_file(p)
    return out


def step_preserve(extracted_dir, working_dir, log, results):
    log("STEP 3 - Hash extracted copies, make them read-only, create working copies")
    before = hash_tree(extracted_dir)
    for rel, h in before.items():
        log("SHA-256 %s  %s" % (h, rel))
    for d, _, files in os.walk(extracted_dir):
        for fn in files:
            make_readonly(os.path.join(d, fn))
    shutil.copytree(extracted_dir, working_dir)
    for d, _, files in os.walk(working_dir):
        for fn in files:
            make_writable(os.path.join(d, fn))
    log("Extracted copies set read-only; working copies created in %s" % working_dir)
    results["hashes_before"] = before
    return before


def analyse_mmssms(path, label, log):
    con = connect_ro(path)
    t = tables(con)
    r = {"label": label,
         "sms": one(con, "SELECT COUNT(*) FROM sms") if "sms" in t else None,
         "mms": one(con, "SELECT COUNT(*) FROM pdu") if "pdu" in t else None,
         "threads": one(con, "SELECT COUNT(*) FROM threads") if "threads" in t else None,
         "page_count": one(con, "PRAGMA page_count"),
         "freelist_count": one(con, "PRAGMA freelist_count")}
    log("%s: SMS=%s MMS=%s threads=%s pages=%s free_pages=%s" %
        (label, r["sms"], r["mms"], r["threads"], r["page_count"], r["freelist_count"]))
    if r["sms"]:
        rows = con.execute("SELECT _id, address, date, type, body FROM sms ORDER BY date").fetchall()
        r["sms_first"] = {"id": rows[0][0], "address": rows[0][1], "raw_date": rows[0][2],
                          "utc": utc(rows[0][2]), "local": local(rows[0][2]), "body": (rows[0][4] or "")[:80]}
        r["sms_last"] = [{"id": x[0], "address": x[1], "utc": utc(x[2]), "local": local(x[2]),
                          "direction": {1: "Received", 2: "Sent"}.get(x[3], x[3]), "body": (x[4] or "")[:80]}
                         for x in rows[-3:]]
    # deletion traces: AUTOINCREMENT numbers that were given but no longer exist
    gaps = {}
    if "sqlite_sequence" in t:
        for name, seq in con.execute("SELECT name, seq FROM sqlite_sequence"):
            if name in t:
                ids = {x[0] for x in con.execute("SELECT _id FROM %s" % name)}
                missing = sorted(set(range(1, int(seq) + 1)) - ids)
                gaps[name] = {"seq": seq, "rows": len(ids), "missing_ids": missing}
                if missing:
                    log("%s: table %s - highest id ever given %s, rows %s, missing ids %s -> rows created then deleted" %
                        (label, name, seq, len(ids), missing), "FIND")
    r["sequence_gaps"] = gaps
    # orphan MMS parts: pieces whose parent MMS (mid) no longer exists in pdu -> leftovers of a deleted MMS
    if "part" in t and "pdu" in t:
        pcols = columns(con, "part")
        want = [c for c in ("_id", "mid", "seq", "ct", "cl", "text", "_data") if c in pcols]
        orphans = []
        for row in con.execute("SELECT %s FROM part WHERE mid NOT IN (SELECT _id FROM pdu) ORDER BY _id" % ", ".join(want)):
            d = dict(zip(want, row))
            if d.get("text"):
                d["text"] = str(d["text"])[:300]
            orphans.append(d)
            log("%s: ORPHAN MMS part _id=%s belongs to mid=%s (MMS no longer exists) type=%s name=%s file=%s text=%s" %
                (label, d.get("_id"), d.get("mid"), d.get("ct"), d.get("cl"), d.get("_data"), (d.get("text") or "")[:80]), "FIND")
        r["orphan_parts"] = orphans
    if r["mms"]:
        r["mms_rows"] = [{"id": x[0], "utc": utc(x[1], seconds=True), "local": local(x[1], seconds=True),
                          "direction": {1: "Received", 2: "Sent"}.get(x[2], x[2])}
                         for x in con.execute("SELECT _id, date, msg_box FROM pdu ORDER BY date")]
    con.close()
    return r


def analyse_whatsapp(path, log):
    con = connect_ro(path)
    t = tables(con)
    tbl = "messages" if "messages" in t else ("message" if "message" in t else None)
    r = {"table": tbl, "tables_total": len(t),
         "page_count": one(con, "PRAGMA page_count"), "freelist_count": one(con, "PRAGMA freelist_count")}
    for extra in ("message_revoked", "message_ephemeral", "message_media"):
        r[extra] = one(con, "SELECT COUNT(*) FROM %s" % extra) if extra in t else None
    if tbl == "messages":
        cols = columns(con, "messages")
        r["rows"] = one(con, "SELECT COUNT(*) FROM messages")
        r["types"] = {str(k): v for k, v in con.execute(
            "SELECT media_wa_type, COUNT(*) FROM messages GROUP BY media_wa_type ORDER BY CAST(media_wa_type AS INTEGER)")}
        want = [c for c in ("_id", "key_from_me", "timestamp", "media_wa_type", "latitude", "longitude",
                            "media_duration", "media_caption") if c in cols]
        locs = []
        for row in con.execute("SELECT %s FROM messages WHERE CAST(media_wa_type AS INTEGER) IN (5, 16) ORDER BY timestamp" % ", ".join(want)):
            d = dict(zip(want, row))
            locs.append({"id": d.get("_id"),
                         "direction": "Sent" if str(d.get("key_from_me")) == "1" else "Received",
                         "utc": utc(d.get("timestamp")), "local": local(d.get("timestamp")),
                         "type": "Location" if str(d.get("media_wa_type")) == "5" else "Live location",
                         "lat_rounded": round(d["latitude"], 2) if d.get("latitude") is not None else None,
                         "lon_rounded": round(d["longitude"], 2) if d.get("longitude") is not None else None,
                         "lat": d.get("latitude"), "lon": d.get("longitude"),
                         "duration": d.get("media_duration"), "caption": d.get("media_caption")})
        r["locations"] = locs
        if len(locs) >= 2 and all(x["lat"] is not None for x in locs):
            import math
            def dist(a, b):
                la1, lo1, la2, lo2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
                h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
                return 2 * 6371000 * math.asin(math.sqrt(h))
            r["locations_max_distance_m"] = round(max(dist(a, b) for i, a in enumerate(locs) for b in locs[i + 1:]), 1)
        log("WhatsApp: table=%s rows=%s types=%s revoked=%s free_pages=%s" %
            (tbl, r["rows"], r["types"], r["message_revoked"], r["freelist_count"]))
        for x in locs:
            log("WhatsApp %s %s %s (local) %s,%s caption=%s" %
                (x["type"], x["direction"], x["local"], x["lat_rounded"], x["lon_rounded"], x["caption"]), "FIND")
        if "locations_max_distance_m" in r:
            log("WhatsApp: largest distance between two shared positions = %s m" % r["locations_max_distance_m"], "FIND")
    for x in r.get("locations", []):  # keep only rounded coordinates in the outputs
        x.pop("lat", None)
        x.pop("lon", None)
    con.close()
    return r


def analyse_accounts(path, log):
    con = connect_ro(path)
    rows = con.execute("SELECT _id, name, type FROM accounts ORDER BY _id").fetchall()  # password column NOT read
    con.close()
    log("Accounts: %d accounts (password column deliberately not read)" % len(rows))
    return {"count": len(rows), "accounts": [{"id": a, "name": b, "type": c} for a, b, c in rows]}


def step_sql(working_dir, log, results):
    log("STEP 4 - SQL analysis on the working copies")
    sql = {}
    p = lambda rel: safe_join(working_dir, rel)
    if os.path.isfile(p(MMS_DE)):
        sql["mmssms_user_de"] = analyse_mmssms(p(MMS_DE), "mmssms.db (user_de)", log)
    if os.path.isfile(p(MMS_ACTIVE)):
        sql["mmssms_data"] = analyse_mmssms(p(MMS_ACTIVE), "mmssms.db (data/data)", log)
    if os.path.isfile(p(WA_DB)):
        sql["whatsapp"] = analyse_whatsapp(p(WA_DB), log)
    if os.path.isfile(p(ACC_DB)):
        sql["accounts"] = analyse_accounts(p(ACC_DB), log)
    results["sql"] = sql
    return sql


def step_compare_aleapp(tsv_dir, sql, log, results):
    log("STEP 5 - Compare with ALEAPP (TSV exports)")
    cmp_rows = []
    if not tsv_dir or not os.path.isdir(tsv_dir):
        log("ALEAPP TSV folder not found (%s) - comparison skipped" % tsv_dir, "WARN")
        results["comparison"] = cmp_rows
        return

    def add(check, aleapp, agent, note=""):
        match = "YES" if str(aleapp) == str(agent) else "NO"
        cmp_rows.append({"check": check, "aleapp": aleapp, "agent": agent, "match": match, "note": note})
        log("%-36s ALEAPP=%-6s AGENT=%-6s %s %s" % (check, aleapp, agent, match, note),
            "INFO" if match == "YES" else "FIND")

    f = os.path.join(tsv_dir, "SMS Messages.tsv")
    if os.path.isfile(f) and "mmssms_data" in sql:
        _, rows = read_tsv(f)
        add("Number of SMS", len(rows), sql["mmssms_data"]["sms"])
    f = os.path.join(tsv_dir, "MMS Messages.tsv")
    if os.path.isfile(f) and "mmssms_data" in sql:
        _, rows = read_tsv(f)
        add("Number of MMS", len(rows), sql["mmssms_data"]["mms"])
    f = os.path.join(tsv_dir, "Accounts_ce.tsv")
    if os.path.isfile(f) and "accounts" in sql:
        _, rows = read_tsv(f)
        add("Number of accounts", len(rows), sql["accounts"]["count"])
    f = os.path.join(tsv_dir, "WhatsApp - Messages.tsv")
    if os.path.isfile(f) and "whatsapp" in sql:
        head, rows = read_tsv(f)
        wa_rows = sql["whatsapp"].get("rows")
        add("WhatsApp messages", len(rows), (wa_rows - 1) if isinstance(wa_rows, int) else wa_rows,
            "(agent excludes the internal row _id 1)")
        mi = head.index("Message") if "Message" in head else None
        ai = head.index("Attachment") if "Attachment" in head else None
        empty = [r for r in rows if mi is not None and not r[mi].strip() and (ai is None or not r[ai].strip())]
        loc_times = {x["utc"] for x in sql["whatsapp"].get("locations", [])}
        explained = [r for r in empty if r[0][:19] in loc_times]  # match on the ALEAPP timestamp (UTC)
        cmp_rows.append({"check": "WhatsApp messages with no text and no attachment in ALEAPP",
                         "aleapp": len(empty),
                         "agent": "%d of them match a location / live-location message (same timestamp)" % len(explained),
                         "match": "EXPLAINED", "note": "content revealed only by SQL; any other empty row is a system message"})
        log("ALEAPP shows %d WhatsApp messages with no text/attachment; %d of them are location messages (timestamps match)" %
            (len(empty), len(explained)), "FIND")
    if "mmssms_data" in sql:
        gaps = sql["mmssms_data"].get("sequence_gaps", {})
        deleted = {k: v["missing_ids"] for k, v in gaps.items() if v["missing_ids"]}
        orph = sql["mmssms_data"].get("orphan_parts", [])
        if orph:
            cmp_rows.append({"check": "Orphan MMS parts (leftovers of a deleted MMS)", "aleapp": "not reported",
                             "agent": ", ".join("part %s (mid %s, %s)" % (o.get("_id"), o.get("mid"), o.get("ct")) for o in orph),
                             "match": "NEW", "note": "see section 3"})
        cmp_rows.append({"check": "Deleted rows (sqlite_sequence gaps) in mmssms.db", "aleapp": "not reported",
                         "agent": json.dumps(deleted) if deleted else "none", "match": "NEW" if deleted else "-",
                         "note": "content not recoverable if free_pages = 0"})
    results["comparison"] = cmp_rows


def step_reverify(extracted_dir, working_dir, before, log, results):
    log("STEP 6 - Re-verify the extracted copies and compare the working copies")
    after = hash_tree(extracted_dir)
    identical = after == before
    log("Extracted copies before/after: %s" % ("IDENTICAL" if identical else "DIFFERENT"),
        "INFO" if identical else "ERROR")
    working = hash_tree(working_dir)
    changed = sorted(k for k in before if working.get(k) != before[k])
    for k in changed:
        log("Working copy modified by SQLite: %s (%s -> %s)" % (k, before[k][:16], (working.get(k) or "")[:16]), "FIND")
    if not changed:
        log("Working copies identical to extracted copies")
    results["reverify"] = {"extracted_identical": identical, "working_copies_changed": changed}


def write_html(path, results):
    e = lambda x: html.escape(str(x))
    tar, integ, sql = results.get("tar", {}), results.get("integrity", {}), results.get("sql", {})
    ok = lambda b: '<b style="color:#1a7f37">MATCH</b>' if b else '<b style="color:#c62828">MISMATCH</b>'
    h = ['<!doctype html><html><head><meta charset="utf-8"><title>Forensic agent report</title>',
         '<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1f2933}'
         'table{border-collapse:collapse;width:100%;margin:8px 0 18px}td,th{border:1px solid #c9d1d9;padding:5px 7px;font-size:13px;text-align:left;vertical-align:top}'
         'th{background:#e8eef5}h1{color:#1d4e89}h2{color:#1d4e89;border-bottom:1px solid #c9d1d9;padding-bottom:3px}code{font-size:12px}'
         '.find{background:#fff8e1}</style></head><body>',
         "<h1>Forensic verification agent — report</h1>",
         "<p>Agent version %s · run started %s · finished %s · all times UTC unless “local” (UTC−4)</p>" %
         (e(VERSION), e(results.get("started")), e(results.get("finished"))),
         "<h2>1. Integrity of the evidence</h2><table>",
         "<tr><th>Evidence</th><td><code>%s</code><br>%s bytes</td></tr>" % (e(tar.get("path")), format(tar.get("size", 0), ",")),
         "<tr><th>MD5</th><td><code>%s</code> vs record <code>%s</code> → %s</td></tr>" %
         (e(tar.get("md5")), e(integ.get("reference", {}).get("md5")), ok(integ.get("md5_match"))),
         "<tr><th>SHA-1</th><td><code>%s</code> vs record <code>%s</code> → %s</td></tr>" %
         (e(tar.get("sha1")), e(integ.get("reference", {}).get("sha1")), ok(integ.get("sha1_match"))),
         "<tr><th>SHA-256</th><td><code>%s</code></td></tr>" % e(tar.get("sha256")),
         "<tr><th>Reference source</th><td>%s</td></tr></table>" % e(integ.get("reference", {}).get("source")),
         "<h2>2. Extracted files</h2><table><tr><th>File inside the image</th><th>Size</th><th>SHA-256 (extracted copy)</th></tr>"]
    for k, v in results.get("extracted", {}).items():
        h.append("<tr><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>" %
                 (e(k), format(v["size"], ","), e(results.get("hashes_before", {}).get(k, ""))))
    h.append("</table><p>Presence checks: %s</p>" % ", ".join(
        "%s: <b>%s</b>" % (e(k), "present" if v else "absent") for k, v in results.get("presence", {}).items()))
    h.append("<h2>3. SMS / MMS</h2><table><tr><th>Database</th><th>SMS</th><th>MMS</th><th>Threads</th><th>Pages</th><th>Free pages</th></tr>")
    for key in ("mmssms_user_de", "mmssms_data"):
        if key in sql:
            r = sql[key]
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                     tuple(e(r.get(x)) for x in ("label", "sms", "mms", "threads", "page_count", "freelist_count")))
    h.append("</table>")
    md = sql.get("mmssms_data", {})
    if md.get("sms_first"):
        f = md["sms_first"]
        h.append("<p>First SMS: raw date <code>%s</code> ms → <b>%s UTC</b> (%s local), from %s: “%s”</p>" %
                 (e(f["raw_date"]), e(f["utc"]), e(f["local"]), e(f["address"]), e(f["body"])))
        h.append("<table><tr><th>Last SMS (UTC)</th><th>Local</th><th>Direction</th><th>Address</th><th>Text</th></tr>")
        for x in md.get("sms_last", []):
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                     (e(x["utc"]), e(x["local"]), e(x["direction"]), e(x["address"]), e(x["body"])))
        h.append("</table>")
    if md.get("sequence_gaps"):
        h.append("<table><tr><th>Table</th><th>Highest id ever given</th><th>Rows now</th><th>Missing ids (created then deleted)</th></tr>")
        for k, v in md["sequence_gaps"].items():
            cls = ' class="find"' if v["missing_ids"] else ""
            h.append("<tr%s><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                     (cls, e(k), e(v["seq"]), e(v["rows"]), e(v["missing_ids"] or "none")))
        h.append("</table>")
    if md.get("orphan_parts"):
        h.append("<p><b>Orphan MMS parts</b> (their MMS no longer exists — leftovers of a deleted MMS):</p>"
                 "<table><tr><th>part _id</th><th>mid (deleted MMS)</th><th>Content type</th><th>Name</th><th>File</th><th>Text</th></tr>")
        for o in md["orphan_parts"]:
            h.append('<tr class="find"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' %
                     tuple(e(o.get(k) or "") for k in ("_id", "mid", "ct", "cl", "_data", "text")))
        h.append("</table>")
    wa = sql.get("whatsapp")
    if wa:
        h.append("<h2>4. WhatsApp</h2><p>Table <code>%s</code>: %s rows; type counts %s; revoked %s; free pages %s.</p>" %
                 (e(wa.get("table")), e(wa.get("rows")), e(wa.get("types")), e(wa.get("message_revoked")), e(wa.get("freelist_count"))))
        if wa.get("locations"):
            h.append("<table><tr><th>_id</th><th>Local time</th><th>Direction</th><th>Type</th><th>Lat (rounded)</th><th>Lon (rounded)</th><th>Duration</th><th>Caption</th></tr>")
            for x in wa["locations"]:
                h.append('<tr class="find"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>' %
                         tuple(e(x.get(k) if x.get(k) is not None else "") for k in
                               ("id", "local", "direction", "type", "lat_rounded", "lon_rounded", "duration", "caption")))
            h.append("</table><p>Largest distance between two shared positions: <b>%s m</b>.</p>" % e(wa.get("locations_max_distance_m")))
    acc = sql.get("accounts")
    if acc:
        h.append("<h2>5. Accounts</h2><p>%d accounts (password column not read): %s</p>" %
                 (acc["count"], e(", ".join(a["name"] for a in acc["accounts"]))))
    h.append("<h2>6. Comparison with ALEAPP</h2><table><tr><th>Check</th><th>ALEAPP</th><th>Agent (SQL)</th><th>Match</th><th>Note</th></tr>")
    for c in results.get("comparison", []):
        cls = ' class="find"' if c["match"] not in ("YES",) else ""
        h.append("<tr%s><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td>%s</td></tr>" %
                 (cls, e(c["check"]), e(c["aleapp"]), e(c["agent"]), e(c["match"]), e(c["note"])))
    rv = results.get("reverify", {})
    h.append("</table><h2>7. Re-verification</h2><p>Extracted copies before/after: <b>%s</b>. Working copies changed by SQLite: %s.</p>" %
             ("IDENTICAL" if rv.get("extracted_identical") else "DIFFERENT", e(rv.get("working_copies_changed") or "none")))
    h.append("<p>Full action log: <code>agent_log.txt</code>. Machine-readable results: <code>results.json</code>.</p></body></html>")
    open(path, "w", encoding="utf-8").write("\n".join(h))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Automated forensic verification agent (Android 11 Pixel 3 image)")
    ap.add_argument("--tar", default=DEFAULT_TAR, help="path of Data.tar (the evidence)")
    ap.add_argument("--image-info", default=DEFAULT_IMAGE_INFO, help="path of image_info.txt (acquisition record)")
    ap.add_argument("--aleapp-tsv", default=DEFAULT_ALEAPP_TSV, help="ALEAPP '_TSV Exports' folder")
    ap.add_argument("--out", default=DEFAULT_OUT, help="folder where the run folder is created")
    a = ap.parse_args()

    run = os.path.join(a.out, "run_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
    extracted, working = os.path.join(run, "extracted"), os.path.join(run, "working")
    os.makedirs(extracted)
    log = Log(os.path.join(run, "agent_log.txt"))
    results = {"agent_version": VERSION, "started": dt.datetime.now().isoformat(timespec="seconds"),
               "python": sys.version.split()[0], "platform": sys.platform, "run_folder": run}
    log("Forensic verification agent v%s - Python %s - output %s" % (VERSION, results["python"], run))
    try:
        ref = parse_image_info(a.image_info, log)
        digests = step_extract_and_hash(a.tar, extracted, log, results)
        step_integrity(digests, ref, log, results)
        before = step_preserve(extracted, working, log, results)
        sql = step_sql(working, log, results)
        step_compare_aleapp(a.aleapp_tsv, sql, log, results)
        step_reverify(extracted, working, before, log, results)
    finally:
        results["finished"] = dt.datetime.now().isoformat(timespec="seconds")
        json.dump(results, open(os.path.join(run, "results.json"), "w", encoding="utf-8"), indent=2, default=str)
        write_html(os.path.join(run, "report.html"), results)
        log("DONE - report: %s" % os.path.join(run, "report.html"))
        log.close()


if __name__ == "__main__":
    main()
