#!/usr/bin/env python3
"""
forensic_agent_v3.py - GENERIC "gap explorer" agent.

Goal: for ANY extraction (Android, iPhone, Windows folder, USB copy...) and ANY forensic tool
report (ALEAPP, iLEAPP, Autopsy export...), find what the tool did NOT read, explore it without
knowing the application in advance, and PROPOSE the next step to the examiner: which file to open,
with which tool, and the ready-made SQL query for DB Browser for SQLite.

The agent contains no application knowledge (no "WhatsApp" or "SMS" rules). It observes generic
signals and builds its own per-case conclusions from them:
    OBSERVE  every file is identified by its signature (SQLite, XML, JSON, JPEG, PNG, ZIP...),
             high-entropy files without signature are flagged as probably encrypted
    COMPARE  the tool report is read and every path it mentions is collected -> coverage gap
    EXPLORE  each database table is sampled: timestamps (format recognised from the number size),
             message-like text, people identifiers (phone, e-mail), coordinates, URLs, binary blobs,
             deleted traces (numbering gaps, free pages, WAL)
    DECIDE   a score and a severity are computed FROM THE DATA (not from fixed labels)
    PROPOSE  ranked proposals with the tool to use and a ready-made query
    RECORD   every decision in agent_log.txt

Evidence is opened read-only; analysis uses working copies; extracted copies are re-hashed.
Standard library only.

Usage:
    python forensic_agent_v3.py --evidence "D:\\Evidence\\Data.tar" --tool-report "D:\\...\\ALEAPP_Output_..." --out "C:\\Enquete\\Agent"
    (--evidence can be a .tar, a .zip or an extracted folder; --record = a text file with the reference hashes)
"""

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import sys
import tarfile
import zipfile

VERSION = "3.0"

BASE = r"D:\Enquete_Android11\02_Travail\Android 11\Android 11 Image with Documentation"
DEFAULTS = {
    "evidence": BASE + r"\Extraction\Android 11 - Pixel 3 - Data.tar",
    "record": BASE + r"\Extraction Info\image_info.txt",
    "tool_report": r"D:\Enquete_Android11\03_Rapports\ALEAPP_Output_2026-10-19_Monday_134141",
    "out": r"C:\Enquete\Agent",
}

MAX_DB = 300 * 1024 * 1024
MAX_TEXT = 5 * 1024 * 1024
SAMPLE_ROWS = 200

SIGNATURES = [  # (bytes, offset, type)
    (b"SQLite format 3\x00", 0, "sqlite"), (b"\xff\xd8\xff", 0, "jpeg"), (b"\x89PNG", 0, "png"),
    (b"PK\x03\x04", 0, "zip"), (b"\x1f\x8b", 0, "gzip"), (b"GIF8", 0, "gif"), (b"RIFF", 0, "riff"),
    (b"%PDF", 0, "pdf"), (b"bplist00", 0, "plist"), (b"ftyp", 4, "mp4"), (b"OggS", 0, "ogg"),
    (b"dex\n", 0, "dex"), (b"\x7fELF", 0, "elf"), (b"<?xml", 0, "xml"), (b"ID3", 0, "mp3"),
    (b"\x37\x7f\x06\x82", 0, "sqlite-wal"), (b"\x37\x7f\x06\x83", 0, "sqlite-wal"),
]

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9.-]+")
# a phone number: "+" and 10-14 digits, or 10-11 digits not looking like a Unix timestamp (1.5e9-1.8e9 s / ms)
RE_PHONE = re.compile(r"(?<![\w@.])(?:\+\d{10,14}|(?!1[5-7]\d{8})\d{10,11})(?![\w.])")
RE_URL = re.compile(r"https?://[^\s\"'<>]+")
RE_PATHTOK = re.compile(r"[A-Za-z0-9_.\-@ ]+(?:/[A-Za-z0-9_.\-@ +]+)+")
MSG_NAMES = re.compile(r"^(body|text|message|msg|content|snippet|caption|subject|comment|note|data|title)$", re.I)
TIME_NAMES = re.compile(r"(time|date|stamp|created|modified|updated|_ts$|^ts$|last_|expire|sent|received)", re.I)
PERSON_NAMES = re.compile(r"(address|sender|recipient|from|to_|number|phone|jid|email|contact|participant|author|user|name)", re.I)
LAT_NAMES = re.compile(r"^(lat|latitude|.*_lat|.*latitude)$", re.I)
LON_NAMES = re.compile(r"^(lon|lng|long|longitude|.*_lon|.*_lng|.*longitude)$", re.I)

TIME_FORMATS = [  # (name, low, high, sql template)
    ("Unix seconds", 9.4e8, 2.0e9, "datetime({c}, 'unixepoch')"),
    ("Unix milliseconds", 9.4e11, 2.0e12, "datetime({c}/1000, 'unixepoch')"),
    ("Unix microseconds", 9.4e14, 2.0e15, "datetime({c}/1000000, 'unixepoch')"),
    ("WebKit/Chrome microseconds since 1601", 1.26e16, 1.40e16, "datetime({c}/1000000 - 11644473600, 'unixepoch')"),
    ("Unix nanoseconds", 9.4e17, 2.0e18, "datetime({c}/1000000000, 'unixepoch')"),
]


# =================================================================== small helpers
class Log:
    def __init__(self, p):
        self.f = open(p, "w", encoding="utf-8")

    def __call__(self, m, lvl="INFO"):
        line = "%s  %-8s %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), lvl, m)
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()


class HashingReader:
    """Reads the evidence once, hashing every byte. If the (USB) disk returns a read error, it waits,
    re-opens the evidence read-only, goes back to the exact byte position and retries."""

    def __init__(self, f, total, path=None, log=None):
        self.f, self.total, self.done, self.nxt = f, total, 0, 0
        self.path, self.log, self.retries = path, log, 0
        self.h = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]

    def _read_retry(self, n):
        for attempt in range(1, 7):
            try:
                return self.f.read(n)
            except OSError as e:
                if not self.path or attempt == 6:
                    raise
                self.retries += 1
                if self.log:
                    self.log("Read error at byte %s (%s) - attempt %d: waiting, re-opening the evidence read-only, "
                             "resuming at the same position" % (format(self.done, ","), e, attempt), "WARN")
                import time
                time.sleep(3 * attempt)
                try:
                    self.f.close()
                except OSError:
                    pass
                try:
                    self.f = open(self.path, "rb")
                    self.f.seek(self.done)
                except OSError:
                    continue

    def read(self, n=-1):
        b = self._read_retry(n)
        if b:
            for h in self.h:
                h.update(b)
            self.done += len(b)
            if self.done >= self.nxt:
                print("      ... %5.1f %%  (%.2f GB read)" % (100.0 * self.done / max(self.total, 1), self.done / 1e9), flush=True)
                self.nxt += 1_000_000_000
        return b

    def drain(self):
        while self.read(8 << 20):
            pass

    def digests(self):
        return {"md5": self.h[0].hexdigest(), "sha1": self.h[1].hexdigest(), "sha256": self.h[2].hexdigest()}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


WIN_BAD = re.compile(r'[<>:"|?*\x00-\x1f]')


def clean_part(part):
    """Make one path component valid on Windows (':' etc. are legal on Android, not on Windows)."""
    return WIN_BAD.sub("_", part).rstrip(" .") or "_"


def rel_key(name):
    """Path of the stored copy, relative to the extraction folder (the original name is kept in the records)."""
    return "/".join(clean_part(p) for p in name.replace("\\", "/").split("/") if p not in ("", ".", ".."))


def safe_join(root, name):
    return os.path.join(root, *rel_key(name).split("/"))


def sniff(head):
    for sig, off, t in SIGNATURES:
        if head[off:off + len(sig)] == sig:
            return t
    s = head.lstrip()[:1]
    if s in (b"{", b"["):
        return "json?"
    if head.lstrip().startswith(b"<"):
        return "xml"
    return None


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c if v)


def path_keys(p):
    parts = [x for x in p.replace("\\", "/").split("/") if x]
    k = 3 if len(parts) >= 3 else len(parts)
    return {"/".join(parts[-k:]).lower()} if k else set()


def qident(x):
    return '"%s"' % str(x).replace('"', '""')


def connect_ro(p):
    try:
        c = sqlite3.connect("file:" + p.replace("\\", "/") + "?mode=ro", uri=True)
        c.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return c
    except sqlite3.Error:
        return sqlite3.connect(p)


def strings_of(b, n=8):
    return [s.decode("ascii", "ignore") for s in re.findall(rb"[\x20-\x7e]{%d,}" % n, b)]


# =================================================================== the agent
class GapAgent:
    def __init__(self, a):
        self.a = a
        self.run = os.path.join(a.out, "run_v3_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.ext, self.work = os.path.join(self.run, "extracted"), os.path.join(self.run, "working")
        os.makedirs(self.ext)
        self.log = Log(os.path.join(self.run, "agent_log.txt"))
        self.R = {"version": VERSION, "started": dt.datetime.now().isoformat(timespec="seconds"), "python": sys.version.split()[0]}
        self.types, self.files, self.dbs, self.encrypted, self.images = {}, 0, {}, [], []
        self.textfiles = {}
        self.renamed = {}
        self.decisions, self.proposals = [], []
        self.covered_keys = set()
        self.tool_files = 0

    def decide(self, trigger, action, result=""):
        self.decisions.append({"trigger": trigger, "action": action, "result": result})
        self.log("trigger: %s | action: %s%s" % (trigger, action, (" | result: " + result) if result else ""), "DECISION")

    # ------------------------------------------------------------- OBSERVE
    def observe(self):
        ev = self.a.evidence
        self.log("OBSERVE - evidence %s" % ev)
        if os.path.isdir(ev):
            self.decide("evidence is a folder", "walk the folder (no container hash possible)")
            for d, _, fs in os.walk(ev):
                for fn in fs:
                    p = os.path.join(d, fn)
                    rel = os.path.relpath(p, ev).replace("\\", "/")
                    with open(p, "rb") as f:
                        self._consider(rel, os.path.getsize(p), f)
            return
        if not os.path.isfile(ev):
            self.log("Evidence not found: %s" % ev, "ERROR")
            raise SystemExit(1)
        size = os.path.getsize(ev)
        with open(ev, "rb") as raw:
            rd = HashingReader(raw, size, ev, self.log)
            if zipfile.is_zipfile(ev):
                self.decide("evidence is a ZIP archive", "read every member")
                with zipfile.ZipFile(ev) as z:
                    for zi in z.infolist():
                        if not zi.is_dir():
                            with z.open(zi) as f:
                                self._consider(zi.filename, zi.file_size, f)
                raw.seek(0)
                rd.drain()
            else:
                self.decide("evidence is a TAR archive", "single streaming pass: hash + identify every file by signature")
                with tarfile.open(fileobj=rd, mode="r|") as tf:
                    for m in tf:
                        if m.isfile():
                            self._consider(m.name.lstrip("./"), m.size, tf.extractfile(m))
                rd.drain()
        self.R["evidence"] = {"path": ev, "size": size, "read_retries": rd.retries, **rd.digests()}
        if rd.retries:
            self.decide("%d read error(s) on the evidence disk" % rd.retries, "re-open and resume at the same byte",
                        "the hashes computed below prove whether the bytes read are correct")

    def _consider(self, name, size, f):
        self.files += 1
        companion = re.search(r"-(wal|shm|journal)$", name)
        head = f.read(4096) if size else b""
        t = sniff(head) or ("empty" if not size else None)
        if t is None and size >= 4096 and entropy(head) > 7.5:
            t = "high-entropy"
        t = t or "other"
        self.types[t] = self.types.get(t, 0) + 1
        if companion and size <= MAX_DB:
            self._save(name, head, f)
            return
        if t == "sqlite" and size <= MAX_DB:
            if self._save(name, head, f):
                self.dbs[name] = {"size": size}
        elif t == "high-entropy" and (re.search(r"\.(db|sqlite\d?|realm)$", name, re.I) or "/databases/" in name):
            self.encrypted.append({"path": name, "size": size, "entropy": round(entropy(head), 2)})
        elif t in ("xml", "json?", "plist") and size <= MAX_TEXT:
            if self._save(name, head, f):
                self.textfiles[name] = {"size": size, "type": t}
        elif t == "jpeg" and b"Exif" in head[:64]:
            gps = (b"\x88\x25" in head) or (b"\x25\x88" in head)
            self.images.append({"path": name, "size": size, "exif": True, "gps_tag": gps})

    def _save(self, name, head, f):
        dest = safe_join(self.ext, name)
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as out:
                out.write(head)
                shutil.copyfileobj(f, out)
        except OSError as e:
            self.log("Could not copy %s (%s) - skipped" % (name, e), "WARN")
            return False
        if rel_key(name) != name:
            self.renamed[name] = rel_key(name)
        return True

    # ------------------------------------------------------------- integrity (generic)
    def integrity(self):
        ev = self.R.get("evidence")
        if not ev:
            return True
        rec = self.a.record
        if not rec or not os.path.isfile(rec):
            self.decide("no reference record given", "continue; integrity not compared", "SHA-256 %s" % ev["sha256"])
            return True
        text = open(rec, encoding="utf-8", errors="ignore").read().lower()
        hits = [k for k in ("md5", "sha1", "sha256") if ev[k] in text]
        if hits:
            self.decide("reference record %s" % os.path.basename(rec), "compare hashes", "MATCH: %s" % ", ".join(hits))
            return True
        self.decide("no hash of the evidence appears in the reference record", "STOP", "evidence not trustworthy")
        return False

    # ------------------------------------------------------------- COMPARE with the tool report
    def read_tool_report(self):
        d = self.a.tool_report
        if not d or not os.path.isdir(d):
            self.decide("no tool report folder", "treat every database as unread by tools")
            return
        for root, _, fs in os.walk(d):
            for fn in fs:
                if not fn.lower().endswith((".html", ".htm", ".tsv", ".csv", ".txt", ".json", ".kml")):
                    continue
                try:
                    txt = open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                self.tool_files += 1
                for tok in RE_PATHTOK.findall(txt):
                    for piece in re.split(r"\s+(?=data/|private/|/data/|storage/|/storage/)", tok):
                        self.covered_keys |= path_keys(piece.strip())
        self.decide("tool report folder with %d text files" % self.tool_files, "collect every file path the tool mentions",
                    "%d path keys collected" % len(self.covered_keys))

    def covered(self, name):
        return bool(path_keys(name) & self.covered_keys)

    # ------------------------------------------------------------- preserve
    def preserve(self):
        self.before = {}
        for d, _, fs in os.walk(self.ext):
            for fn in fs:
                p = os.path.join(d, fn)
                self.before[os.path.relpath(p, self.ext).replace("\\", "/")] = sha256_file(p)
                os.chmod(p, stat.S_IREAD)
        shutil.copytree(self.ext, self.work)
        for d, _, fs in os.walk(self.work):
            for fn in fs:
                os.chmod(os.path.join(d, fn), stat.S_IREAD | stat.S_IWRITE)
        seen = {}
        for n in sorted(self.dbs, key=lambda x: (x.count("/user/0/"), x)):
            h = self.before.get(rel_key(n))
            self.dbs[n]["sha256"] = h
            if h in seen:
                self.dbs[n]["duplicate_of"] = seen[h]
            else:
                seen[h] = n
        if self.renamed:
            self.decide("%d file names contain characters forbidden on Windows (e.g. ':')" % len(self.renamed),
                        "store the copies under a cleaned name, keep the original name in all records",
                        "e.g. %s" % next(iter(self.renamed)))
        dup = sum(1 for x in self.dbs.values() if x.get("duplicate_of"))
        self.decide("%d databases are byte-identical copies" % dup, "explore one copy only") if dup else None

    # ------------------------------------------------------------- EXPLORE databases
    def explore(self):
        n_unread = 0
        for name, info in sorted(self.dbs.items()):
            if info.get("duplicate_of"):
                continue
            info["read_by_tool"] = self.covered(name) if self.covered_keys else False
            n_unread += not info["read_by_tool"]
            p = safe_join(self.work, name)
            try:
                con = connect_ro(p)
                tabs = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'android_%'")]
                info["freelist"] = con.execute("PRAGMA freelist_count").fetchone()[0]
                info["tables"] = []
                seq = {}
                try:
                    seq = dict(con.execute("SELECT name, seq FROM sqlite_sequence").fetchall())
                except sqlite3.Error:
                    pass
                for t in tabs:
                    ti = self._explore_table(con, t, seq.get(t))
                    if ti:
                        info["tables"].append(ti)
                con.close()
            except sqlite3.Error as e:
                info["error"] = str(e)
        uniq = sum(1 for x in self.dbs.values() if not x.get("duplicate_of"))
        self.R["coverage"] = {"databases": uniq, "unread_by_tool": n_unread, "read_by_tool": uniq - n_unread}
        self.decide("%d unique databases; tool report mentions %d of them" % (uniq, uniq - n_unread),
                    "explore all tables, prioritise the %d databases the tool did not read" % n_unread,
                    "coverage gap = %.0f %%" % (100.0 * n_unread / max(uniq, 1)))

    def _explore_table(self, con, t, seq):
        try:
            cols = [(r[1], (r[2] or "").upper()) for r in con.execute("PRAGMA table_info(%s)" % qident(t))]
            n = con.execute("SELECT COUNT(*) FROM %s" % qident(t)).fetchone()[0]
        except sqlite3.Error:
            return None
        if not n:
            return None
        rows = con.execute("SELECT * FROM %s LIMIT %d" % (qident(t), SAMPLE_ROWS)).fetchall()
        names = [c[0] for c in cols]
        sig = {"time": [], "message": [], "person": [], "coords": None, "url": 0, "email": 0, "phone": 0, "blob": []}
        for i, (c, typ) in enumerate(cols):
            vals = [r[i] for r in rows if i < len(r) and r[i] is not None]
            if not vals:
                continue
            nums = [v for v in vals if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if nums and len(nums) >= 0.6 * len(vals):
                med = sorted(nums)[len(nums) // 2]
                for fmt, lo, hi, tpl in TIME_FORMATS:
                    if lo <= med <= hi and (TIME_NAMES.search(c) or fmt != "Unix seconds"):
                        sig["time"].append({"col": c, "format": fmt, "sql": tpl.format(c=qident(c)),
                                            "min": tpl.format(c=str(min(nums))), "max_raw": max(nums), "min_raw": min(nums)})
                        break
            texts = [v for v in vals if isinstance(v, str)]
            if texts:
                avg = sum(len(x) for x in texts) / len(texts)
                spaced = sum(1 for x in texts if " " in x.strip()) / len(texts)
                if MSG_NAMES.match(c) and avg > 3 or (avg > 25 and spaced > 0.5):
                    sig["message"].append(c)
                e = sum(1 for x in texts if RE_EMAIL.search(x))
                ph = sum(1 for x in texts if RE_PHONE.search(x))
                u = sum(1 for x in texts if RE_URL.search(x))
                sig["email"] += e
                sig["phone"] += ph
                sig["url"] += u
                if (e or ph) and c not in sig["person"]:
                    sig["person"].append(c)
            if PERSON_NAMES.search(c) and c not in sig["person"] and texts:
                sig["person"].append(c)
            blobs = [v for v in vals if isinstance(v, (bytes, bytearray))]
            if blobs:
                kind = sniff(bytes(blobs[0][:16])) or ("protobuf?" if blobs[0][:1] in (b"\x08", b"\x0a", b"\x10", b"\x12", b"\x1a") else "binary")
                sig["blob"].append({"col": c, "kind": kind})
        lat = next((c for c in names if LAT_NAMES.match(c)), None)
        lon = next((c for c in names if LON_NAMES.match(c)), None)
        if lat and lon:
            li, gi = names.index(lat), names.index(lon)
            pts = [(r[li], r[gi]) for r in rows if isinstance(r[li], (int, float)) and isinstance(r[gi], (int, float))
                   and r[li] and r[gi] and -90 <= r[li] <= 90 and -180 <= r[gi] <= 180]
            if pts:
                sig["coords"] = {"lat": lat, "lon": lon, "points": len(pts)}
        gaps = None
        if isinstance(seq, int) and "_id" in names and seq <= 2_000_000:
            ids = {r[0] for r in con.execute("SELECT _id FROM %s" % qident(t))}
            miss = seq - len([i for i in ids if isinstance(i, int) and 1 <= i <= seq])
            if miss > 0:
                gaps = {"highest_id": seq, "rows": n, "missing": miss}
        return {"table": t, "rows": n, "columns": names, "signals": sig, "gaps": gaps}

    # ------------------------------------------------------------- deleted data (generic)
    def deleted_data(self):
        for name, info in self.dbs.items():
            if info.get("duplicate_of"):
                continue
            p = safe_join(self.work, name)
            if info.get("freelist"):
                data = open(p, "rb").read()
                ps = int.from_bytes(data[16:18], "big")
                ps = 65536 if ps == 1 else ps
                trunk, pages, seen = int.from_bytes(data[32:36], "big"), [], set()
                while trunk and trunk not in seen and len(seen) < 100000:
                    seen.add(trunk)
                    pg = data[(trunk - 1) * ps:trunk * ps]
                    if len(pg) < 8:
                        break
                    pages.append(trunk)
                    pages += [int.from_bytes(pg[8 + 4 * i:12 + 4 * i], "big") for i in range(min(int.from_bytes(pg[4:8], "big"), (ps - 8) // 4))]
                    trunk = int.from_bytes(pg[0:4], "big")
                txt = []
                for pn in pages:
                    txt += strings_of(data[(pn - 1) * ps:pn * ps])
                info["free_page_strings"] = list(dict.fromkeys(txt))
            wal = p + "-wal"
            if os.path.isfile(wal) and os.path.getsize(wal) > 32:
                w = open(wal, "rb").read()
                main = set(strings_of(open(p, "rb").read())) if os.path.getsize(p) < 100 << 20 else set()
                info["wal_only_strings"] = [s for s in dict.fromkeys(strings_of(w)) if s not in main]

    # ------------------------------------------------------------- DECIDE + PROPOSE
    def score_and_propose(self):
        for name, info in self.dbs.items():
            if info.get("duplicate_of") or info.get("error"):
                continue
            unread = not info.get("read_by_tool")
            # a database is "personal" if any of its tables holds messages, people identifiers or coordinates;
            # numbering gaps are only meaningful in timestamped tables of such databases
            db_personal = any(t["signals"]["message"] or t["signals"]["coords"] or t["signals"]["phone"] or t["signals"]["email"]
                              for t in info.get("tables", []))
            for ti in info.get("tables", []):
                s = ti["signals"]
                score, why = 0, []
                if s["time"]:
                    score += 3; why.append("timestamps (%s)" % ", ".join("%s: %s" % (x["col"], x["format"]) for x in s["time"][:3]))
                if s["message"]:
                    score += 3; why.append("message-like text in %s" % ", ".join(s["message"][:3]))
                if s["phone"] or s["email"]:
                    score += 2; why.append("%d phone numbers, %d e-mail addresses in the sample" % (s["phone"], s["email"]))
                elif s["person"]:
                    score += 1; why.append("identity columns %s" % ", ".join(s["person"][:3]))
                if s["coords"]:
                    score += 4; why.append("GPS coordinates (%s/%s, %d points)" % (s["coords"]["lat"], s["coords"]["lon"], s["coords"]["points"]))
                if s["url"]:
                    score += 1; why.append("%d URLs" % s["url"])
                if any(b["kind"] == "protobuf?" for b in s["blob"]):
                    score += 1; why.append("binary blobs that look like protobuf")
                deleted = ti.get("gaps") if (ti.get("gaps") and db_personal and s["time"]) else None
                if deleted:
                    score += 3; why.append("%d row(s) created then deleted (numbering gap)" % deleted["missing"])
                if unread:
                    score = round(score * 1.5, 1); why.append("NOT read by the tool report")
                if score < 4:
                    continue
                if unread and (s["coords"] or (s["message"] and s["time"] and (s["phone"] or s["email"]))):
                    sev = "HIGH"
                elif deleted or (unread and score >= 6):
                    sev = "MEDIUM" if not deleted or not unread else "HIGH"
                else:
                    sev = "INFO"
                self.proposals.append({"severity": sev, "score": score, "file": name, "table": ti["table"], "rows": ti["rows"],
                                       "read_by_tool": not unread, "why": why, "tool": "DB Browser for SQLite (open read-only, Execute SQL tab)",
                                       "query": self._query(ti)})
            fps = info.get("free_page_strings") or []
            if len(fps) >= 5:
                self.proposals.append({"severity": "MEDIUM", "score": 5 + min(len(fps), 500) / 100, "file": name, "table": "(free pages)",
                                       "rows": len(fps), "read_by_tool": not unread,
                                       "why": ["%d text fragments in free (deleted) pages, e.g. %s" % (len(fps), "; ".join(x[:40] for x in fps[:2]))],
                                       "tool": "SQLite deleted-record recovery tool (e.g. Undark, bring2lite) or a hex viewer",
                                       "query": "-- see carved/%s.freepages.txt" % name.replace("/", "__")})
            wos = info.get("wal_only_strings") or []
            if len(wos) >= 5:
                self.proposals.append({"severity": "INFO", "score": 4 + min(len(wos), 300) / 100, "file": name + "-wal", "table": "(WAL)",
                                       "rows": len(wos), "read_by_tool": not unread,
                                       "why": ["%d text fragments only in the WAL (recent or older page versions)" % len(wos)],
                                       "tool": "WAL parser / hex viewer; compare with the database opened WITHOUT the WAL",
                                       "query": "-- see carved/%s.wal_only.txt" % name.replace("/", "__")})
        for e in self.encrypted:
            self.proposals.append({"severity": "MEDIUM", "score": 4, "file": e["path"], "table": "(no SQLite signature)", "rows": "",
                                   "read_by_tool": self.covered(e["path"]), "why": ["database-like file with high entropy (%s bits/byte): probably encrypted" % e["entropy"]],
                                   "tool": "Key required: look for a key file / keystore entry of the same app; otherwise report as a limitation", "query": ""})
        for name, tf in self.textfiles.items():
            p = safe_join(self.work, name)
            txt = open(p, encoding="utf-8", errors="ignore").read()
            ph, em, ur = len(RE_PHONE.findall(txt)), len(RE_EMAIL.findall(txt)), len(RE_URL.findall(txt))
            ts = len(re.findall(r"(?<!\d)1[5-6]\d{8}(\d{3})?(?!\d)", txt))
            sc = 2 * bool(ph or em) + bool(ur) + bool(ts) + 1.5 * (not self.covered(name))
            if sc >= 3.5:
                self.proposals.append({"severity": "INFO", "score": sc, "file": name, "table": "(%s file)" % tf["type"].strip("?"),
                                       "rows": "", "read_by_tool": self.covered(name),
                                       "why": ["%d phone numbers, %d e-mails, %d URLs, %d Unix timestamps" % (ph, em, ur, ts)],
                                       "tool": "Text editor / XML or JSON viewer", "query": ""})
        gps = [i for i in self.images if i["gps_tag"]]
        if gps:
            self.proposals.append({"severity": "MEDIUM", "score": 6, "file": "%d JPEG files" % len(gps), "table": "(EXIF GPS)",
                                   "rows": len(gps), "read_by_tool": None, "why": ["JPEG photos whose EXIF header contains a GPS block, e.g. %s" % gps[0]["path"]],
                                   "tool": "ExifTool: exiftool -gps:all -datetimeoriginal -model <file>", "query": ""})
        order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        self.proposals.sort(key=lambda x: (order[x["severity"]], -x["score"]))
        for p in self.proposals[:40]:
            self.decide("%s %s.%s (score %s)" % (p["severity"], p["file"].split("/")[-1], p["table"], p["score"]),
                        "propose: %s" % p["tool"].split("(")[0].strip(), "; ".join(p["why"])[:220])

    def _query(self, ti):
        s = ti["signals"]
        sel, order = [], None
        for t in s["time"][:2]:
            sel.append("%s AS %s" % (t["sql"], qident(t["col"] + "_utc")))
            order = order or qident(t["col"])
        keep = []
        for c in s["person"][:3] + s["message"][:3] + ([s["coords"]["lat"], s["coords"]["lon"]] if s["coords"] else []):
            if c not in keep:
                keep.append(c)
        cols = ", ".join([qident(c) for c in keep] + sel) or "*"
        q = "SELECT %s%s FROM %s" % ("_id, " if "_id" in ti["columns"] and cols != "*" else "", cols, qident(ti["table"]))
        if order:
            q += " ORDER BY %s" % order
        return q + ";"

    # ------------------------------------------------------------- re-verify + outputs
    def reverify(self):
        after = {}
        for d, _, fs in os.walk(self.ext):
            for fn in fs:
                p = os.path.join(d, fn)
                after[os.path.relpath(p, self.ext).replace("\\", "/")] = sha256_file(p)
        self.R["reverify"] = {"files": len(after), "identical": after == self.before}
        self.log("RE-VERIFY %d extracted files: %s" % (len(after), "IDENTICAL" if after == self.before else "DIFFERENT"))

    def write_outputs(self):
        cdir = os.path.join(self.run, "carved")
        os.makedirs(cdir, exist_ok=True)
        for n, i in self.dbs.items():
            for key, suf in (("free_page_strings", "freepages"), ("wal_only_strings", "wal_only")):
                if i.get(key):
                    open(os.path.join(cdir, "%s.%s.txt" % (n.replace("/", "__"), suf)), "w", encoding="utf-8").write("\n".join(i[key]))
        with open(os.path.join(self.run, "proposals.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["severity", "score", "file", "table", "rows", "read_by_tool", "why", "tool", "query"])
            for p in self.proposals:
                w.writerow([p["severity"], p["score"], p["file"], p["table"], p["rows"], p["read_by_tool"], " | ".join(p["why"]), p["tool"], p["query"]])
        with open(os.path.join(self.run, "queries_for_db_browser.sql"), "w", encoding="utf-8") as f:
            for p in self.proposals:
                if p["query"].startswith("SELECT"):
                    f.write("-- [%s] %s  (open: %s)\n%s\n\n" % (p["severity"], "; ".join(p["why"]), p["file"], p["query"]))
        slim = {n: {k: v for k, v in i.items() if k not in ("free_page_strings", "wal_only_strings")} for n, i in self.dbs.items()}
        self.R.update({"finished": dt.datetime.now().isoformat(timespec="seconds"), "files_observed": self.files, "types": self.types,
                       "encrypted_candidates": self.encrypted, "decisions": self.decisions, "proposals": self.proposals, "databases": slim, "renamed_for_windows": self.renamed})
        json.dump(self.R, open(os.path.join(self.run, "results.json"), "w", encoding="utf-8"), indent=1, default=str)
        write_html(os.path.join(self.run, "report.html"), self)
        self.log("DONE - %d proposals - report: %s" % (len(self.proposals), os.path.join(self.run, "report.html")))

    def go(self):
        self.log("Generic gap-explorer agent v%s - Python %s - output %s" % (VERSION, self.R["python"], self.run))
        try:
            self.observe()
            self.log("Observed %s files by signature: %s" % (format(self.files, ","), ", ".join("%s %d" % kv for kv in sorted(self.types.items(), key=lambda x: -x[1])[:12])))
            if not self.integrity():
                return
            self.read_tool_report()
            self.preserve()
            self.explore()
            self.deleted_data()
            self.score_and_propose()
            self.reverify()
        finally:
            self.write_outputs()


def write_html(path, ag):
    e = lambda x: html.escape(str(x))
    R, ev, cov = ag.R, ag.R.get("evidence", {}), ag.R.get("coverage", {})
    col = {"HIGH": "#c62828", "MEDIUM": "#b26a00", "INFO": "#1d4e89"}
    h = ['<!doctype html><html><head><meta charset="utf-8"><title>Gap explorer agent</title><style>'
         'body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1f2933}'
         'table{border-collapse:collapse;width:100%;margin:8px 0 18px}td,th{border:1px solid #c9d1d9;padding:5px 7px;font-size:13px;text-align:left;vertical-align:top}'
         'th{background:#e8eef5}h1,h2{color:#1d4e89}h2{border-bottom:1px solid #c9d1d9;padding-bottom:3px}code,pre{font-size:12px}'
         'pre{background:#f6f8fa;padding:6px;white-space:pre-wrap;word-break:break-all;margin:4px 0}td code{word-break:break-all}table{table-layout:fixed}.box{background:#f3f6f9;border-left:4px solid #1d4e89;padding:8px 12px}</style></head><body>',
         "<h1>Gap explorer agent — what the tools did not read, and what to do next</h1>",
         "<p>Agent v%s · %s → %s</p>" % (e(VERSION), e(R.get("started")), e(R.get("finished"))),
         '<div class="box">The agent knows no application. It identifies every file by its signature, collects the paths mentioned in '
         'the tool report, explores every database table for generic signals (timestamps, message-like text, phone numbers, e-mails, '
         'coordinates, URLs, blobs, deleted traces), scores them, and proposes the next step. <b>Every proposal must be verified by the examiner.</b></div>',
         "<h2>1. Evidence and coverage</h2><table><col style='width:18%'><col>",
         "<tr><th>Evidence</th><td><code>%s</code> %s</td></tr>" % (e(ev.get("path", ag.a.evidence)), ("— %s bytes" % format(ev["size"], ",")) if ev else ""),
         "<tr><th>SHA-256</th><td><code>%s</code></td></tr>" % e(ev.get("sha256", "n/a (folder)")),
         "<tr><th>Files observed</th><td>%s — by signature: %s</td></tr>" % (format(ag.files, ","), e(", ".join("%s %d" % kv for kv in sorted(ag.types.items(), key=lambda x: -x[1])))),
         "<tr><th>Tool report</th><td><code>%s</code> — %d text files read, %d path keys</td></tr>" % (e(ag.a.tool_report), ag.tool_files, len(ag.covered_keys)),
         "<tr><th>Coverage</th><td><b>%s</b> unique databases; mentioned by the tool: <b>%s</b>; <b style='color:#c62828'>not read by the tool: %s</b></td></tr>" %
         (e(cov.get("databases")), e(cov.get("read_by_tool")), e(cov.get("unread_by_tool"))),
         "<tr><th>Re-verification</th><td>%s extracted files: <b>%s</b></td></tr></table>" %
         (e(R.get("reverify", {}).get("files")), "IDENTICAL" if R.get("reverify", {}).get("identical") else "see log"),
         "<h2>2. Proposals for the examiner (ranked)</h2><table><tr><th style='width:4%'>#</th><th style='width:9%'>Severity</th><th style='width:25%'>Where</th><th style='width:29%'>Why (signals observed)</th><th style='width:33%'>Tool and query</th></tr>"]
    for i, p in enumerate(ag.proposals[:60], 1):
        h.append('<tr><td>%d</td><td><b style="color:%s">%s</b><br>score %s</td><td><code>%s</code><br>table <b>%s</b> · %s rows<br>%s</td>'
                 '<td>%s</td><td>%s%s</td></tr>' %
                 (i, col[p["severity"]], p["severity"], e(p["score"]), e(p["file"]), e(p["table"]), e(p["rows"]),
                  "read by tool" if p["read_by_tool"] else ("<b>not read by tool</b>" if p["read_by_tool"] is False else ""),
                  "<br>".join("• " + e(w) for w in p["why"]), e(p["tool"]) + (("<br>open the copy: <code>working\\%s</code>" % e(rel_key(p["file"]).replace("/", "\\")))
                                                                    if p["query"].startswith("SELECT") else ""),
                  ("<pre>%s</pre>" % e(p["query"])) if p["query"] else ""))
    h.append("</table><p>All proposals: <code>proposals.csv</code>; all queries ready to paste in DB Browser: <code>queries_for_db_browser.sql</code>.</p>")
    h.append("<h2>3. Decisions</h2><table><tr><th>Observed</th><th>Action</th><th>Result</th></tr>")
    for d in ag.decisions[:80]:
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(d["trigger"]), e(d["action"]), e(d["result"])))
    h.append("</table><h2>4. How severity is decided (from the data)</h2><table><tr><th>Severity</th><th>Condition</th></tr>"
             "<tr><td><b>HIGH</b></td><td>not read by the tool AND (coordinates, OR message-like text + timestamps + phone numbers / e-mails); or deleted rows in such a database that the tool did not read</td></tr>"
             "<tr><td><b>MEDIUM</b></td><td>deleted rows in a timestamped table of a database holding personal data; or unread table with a high score; free pages with text; encrypted database; photos with GPS</td></tr>"
             "<tr><td><b>INFO</b></td><td>interesting but already read by the tool, or weak signals</td></tr></table>"
             "<p>Numbering gaps in tables without personal data or timestamps (settings, caches) are ignored: they are normal application behaviour.</p></body></html>")
    open(path, "w", encoding="utf-8").write("\n".join(h))


def main():
    ap = argparse.ArgumentParser(description="Generic gap-explorer forensic agent")
    ap.add_argument("--evidence", default=DEFAULTS["evidence"], help=".tar, .zip or folder")
    ap.add_argument("--record", default=DEFAULTS["record"], help="text file with reference hashes (optional)")
    ap.add_argument("--tool-report", default=DEFAULTS["tool_report"], help="folder of a tool report (ALEAPP, iLEAPP, ...)")
    ap.add_argument("--out", default=DEFAULTS["out"])
    GapAgent(ap.parse_args()).go()


if __name__ == "__main__":
    main()
