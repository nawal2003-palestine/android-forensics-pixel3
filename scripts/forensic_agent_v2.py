#!/usr/bin/env python3
"""
forensic_agent_v2.py - Triage AGENT for an Android file-system extraction (.tar).

Unlike a fixed script, the agent works in a loop:
    OBSERVE  -> it discovers the evidence by itself (every SQLite database is found by its
                signature "SQLite format 3", not from a list written in advance)
    DECIDE   -> it applies decision RULES to what it observed (each decision is logged with its reason)
    ACT      -> it runs the action chosen by the rule (stop, carve free pages, read a WAL file,
                decrypt a WhatsApp backup, flag a deletion, compare with ALEAPP ...)
    RECORD   -> every observation, decision and result goes to agent_log.txt (chain of custody)
and it repeats until no rule produces a new action.

Rules (R1..R10) are listed in RULES below. The evidence is opened read-only and never modified;
all analysis is done on working copies, and the extracted copies are re-hashed at the end.

Requirements: Python 3.8+ (standard library). Optional: "pip install pycryptodome" to let the
agent decrypt WhatsApp .crypt12 backups (rule R7). Without it, the agent records why it skipped.

Usage (Windows PowerShell):
    python forensic_agent_v2.py
    python forensic_agent_v2.py --tar "D:\\Evidence\\Data.tar" --aleapp-tsv "D:\\...\\_TSV Exports" --out "C:\\Enquete\\Agent"
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
import zlib

VERSION = "2.0"

BASE = r"D:\Enquete_Android11\02_Travail\Android 11\Android 11 Image with Documentation"
DEFAULT_TAR = BASE + r"\Extraction\Android 11 - Pixel 3 - Data.tar"
DEFAULT_IMAGE_INFO = BASE + r"\Extraction Info\image_info.txt"
DEFAULT_ALEAPP_TSV = r"D:\Enquete_Android11\03_Rapports\ALEAPP_Output_2026-10-19_Monday_134141\_TSV Exports"
DEFAULT_OUT = r"C:\Enquete\Agent"

SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_EXTRACT = 300 * 1024 * 1024          # do not extract single databases larger than 300 MB
COMPANIONS = ("-wal", "-shm", "-journal")

# Knowledge base: packages that indicate privacy / concealment / rooting tools
PRIVACY_APPS = {
    "com.hld.anzenbokusucal": "HLD Vault (photo vault)",
    "com.thinkyeah.galleryvault": "GalleryVault (photo vault)",
    "com.topjohnwu.magisk": "Magisk (root manager)",
    "org.thoughtcrime.securesms": "Signal (encrypted messenger)",
    "com.wire": "Wire (encrypted messenger)",
    "com.silentcircle.silentphone": "Silent Phone (encrypted messenger)",
    "com.radicalapps.cyberdust": "Dust (ephemeral messenger)",
    "ch.protonmail.android": "ProtonMail (encrypted e-mail)",
    "de.tutao.tutanota": "Tutanota (encrypted e-mail)",
    "org.torproject.torbrowser": "Tor Browser (anonymous browsing)",
    "com.wickr.pro": "Wickr (encrypted messenger)",
}

RULES = [
    ("R1", "Hashes do not match the acquisition record", "STOP the analysis: the evidence cannot be trusted"),
    ("R2", "Two databases have the same SHA-256", "Analyse only one copy and record the link (e.g. /data/user/0 = /data/data)"),
    ("R3", "A database has free pages (freelist_count > 0)", "Carve the free pages for readable text (possible deleted records)"),
    ("R4", "A database has a non-empty WAL file", "Read the WAL frames and list text present only in the WAL"),
    ("R5", "sqlite_sequence shows ids that no longer exist", "Flag rows created then deleted"),
    ("R6", "A file named .db has no SQLite signature", "Flag it as a probably encrypted database"),
    ("R7", "A WhatsApp key file and a .crypt12 backup are both present", "Decrypt the backup, verify it is SQLite, compare it with msgstore.db"),
    ("R8", "A privacy / concealment / root app folder is present", "Flag the app and list its databases"),
    ("R9", "A known database is found (SMS, WhatsApp, accounts, Magisk log)", "Run the specialised analysis for that database"),
    ("R10", "ALEAPP TSV exports are available", "Compare the agent's counts with ALEAPP's"),
]


# ======================================================================= utilities
class Log:
    def __init__(self, path):
        self.f = open(path, "w", encoding="utf-8")

    def __call__(self, msg, level="INFO"):
        line = "%s  %-8s %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, msg)
        print(line, flush=True)
        self.f.write(line + "\n")
        self.f.flush()

    def close(self):
        self.f.close()


class HashingReader:
    def __init__(self, f, total):
        self.f, self.total = f, total
        self.h = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        self.done, self.next_report = 0, 0

    def read(self, n=-1):
        b = self.f.read(n)
        if b:
            for h in self.h:
                h.update(b)
            self.done += len(b)
            if self.done >= self.next_report:
                print("      ... %5.1f %%  (%.2f GB read)" % (100.0 * self.done / max(self.total, 1), self.done / 1e9), flush=True)
                self.next_report += 1_000_000_000
        return b

    def drain(self):
        while self.read(8 * 1024 * 1024):
            pass

    def digests(self):
        return {"md5": self.h[0].hexdigest(), "sha1": self.h[1].hexdigest(), "sha256": self.h[2].hexdigest()}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def safe_join(root, name):
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return os.path.join(root, *parts)


def utc(v, seconds=False):
    try:
        x = int(v) if seconds else int(v) / 1000.0
        return dt.datetime.fromtimestamp(x, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def local(v, seconds=False, off=-4):
    try:
        x = int(v) if seconds else int(v) / 1000.0
        return (dt.datetime.fromtimestamp(x, dt.timezone.utc) + dt.timedelta(hours=off)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def connect_ro(path):
    try:
        con = sqlite3.connect("file:" + path.replace("\\", "/") + "?mode=ro", uri=True)
        con.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return con
    except sqlite3.Error:
        return sqlite3.connect(path)


def tables(con):
    return [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def columns(con, t):
    return [r[1] for r in con.execute('PRAGMA table_info("%s")' % t.replace('"', '""'))]


def q1(con, sql):
    try:
        r = con.execute(sql).fetchone()
        return r[0] if r else None
    except sqlite3.Error:
        return None


def strings_of(data, n=8):
    return [s.decode("ascii", "ignore") for s in re.findall(rb"[\x20-\x7e]{%d,}" % n, data)]


def read_tsv(path):
    csv.field_size_limit(min(sys.maxsize, 2 ** 31 - 1))
    with open(path, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f, delimiter="\t"))
    return (rows[0], rows[1:]) if rows else ([], [])


# ======================================================================= the agent
class Agent:
    def __init__(self, args):
        self.a = args
        self.run = os.path.join(args.out, "run_v2_" + dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.ext = os.path.join(self.run, "extracted")
        self.work = os.path.join(self.run, "working")
        self.carved = os.path.join(self.run, "carved")
        for d in (self.ext, self.carved):
            os.makedirs(d)
        self.log = Log(os.path.join(self.run, "agent_log.txt"))
        self.decisions, self.findings = [], []
        self.R = {"agent_version": VERSION, "started": dt.datetime.now().isoformat(timespec="seconds"),
                  "python": sys.version.split()[0], "run_folder": self.run}
        self.dbs = {}            # path in image -> info
        self.no_sig_db = []      # .db files without SQLite signature
        self.other_files = {}    # key / backup files extracted for rules
        self.index_count = 0
        self.app_dirs = set()

    # ---------------------------------------------------------------- recording helpers
    def decide(self, rule, trigger, action, result=""):
        self.decisions.append({"rule": rule, "trigger": trigger, "action": action, "result": result})
        self.log("%s | trigger: %s | action: %s%s" % (rule, trigger, action, (" | result: " + result) if result else ""), "DECISION")

    def find(self, severity, question, text, source):
        self.findings.append({"severity": severity, "question": question, "finding": text, "source": source})
        self.log("[%s][%s] %s  (source: %s)" % (severity, question, text, source), "FINDING")

    # ---------------------------------------------------------------- OBSERVE 1: one pass over the evidence
    def observe_evidence(self):
        tar = self.a.tar
        self.log("OBSERVE - reading the evidence once: hashing + discovering databases by signature")
        if not os.path.isfile(tar):
            self.log("Evidence not found: %s" % tar, "ERROR")
            raise SystemExit(1)
        size = os.path.getsize(tar)
        self.log("Evidence %s (%s bytes), opened read-only" % (tar, format(size, ",")))
        companions = {}
        wa_backup = re.compile(r"WhatsApp/Databases/.*\.crypt1[2-5]$")
        with open(tar, "rb") as raw:
            rd = HashingReader(raw, size)
            with tarfile.open(fileobj=rd, mode="r|") as tf:
                for m in tf:
                    name = m.name.lstrip("./")
                    self.index_count += 1
                    mm = re.match(r"data/data/([^/]+)/", name)
                    if mm:
                        self.app_dirs.add(mm.group(1))
                    if not m.isfile() or m.size == 0 and not name.endswith(COMPANIONS):
                        continue
                    if name.endswith(COMPANIONS) and m.size <= MAX_EXTRACT:
                        companions[name] = self._save(tf, m, name)
                        continue
                    if name == "data/data/com.whatsapp/files/key" or wa_backup.search(name):
                        self.other_files[name] = self._save(tf, m, name)
                        continue
                    if m.size < 512 or m.size > MAX_EXTRACT:
                        continue
                    f = tf.extractfile(m)
                    head = f.read(16)
                    if head == SQLITE_MAGIC:
                        dest = safe_join(self.ext, name)
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        with open(dest, "wb") as out:
                            out.write(head)
                            shutil.copyfileobj(f, out)
                        self.dbs[name] = {"size": m.size}
                    elif re.search(r"\.(db|sqlite|sqlite3)$", name, re.I):
                        self.no_sig_db.append({"path": name, "size": m.size, "first_bytes": head[:8].hex()})
            rd.drain()
        # keep only companions whose main database was extracted
        for c, dest in companions.items():
            base = re.sub(r"-(wal|shm|journal)$", "", c)
            if base in self.dbs:
                self.dbs[base].setdefault("companions", []).append(c)
            else:
                os.remove(dest)
        self.R["tar"] = {"path": tar, "size": size, **rd.digests()}
        self.log("Observed %s entries; %d SQLite databases found by signature; %d .db files without signature; "
                 "%d app data folders" % (format(self.index_count, ","), len(self.dbs), len(self.no_sig_db), len(self.app_dirs)))

    def _save(self, tf, m, name):
        dest = safe_join(self.ext, name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as out:
            shutil.copyfileobj(tf.extractfile(m), out)
        return dest

    # ---------------------------------------------------------------- R1 integrity
    def rule_integrity(self):
        d = self.R["tar"]
        cands = {"md5": [], "sha1": []}
        src = self.a.image_info
        if src and os.path.isfile(src):
            for line in open(src, encoding="utf-8", errors="ignore").read().splitlines():
                u = line.upper()
                if "MD5" in u:
                    cands["md5"] += re.findall(r"\b([0-9A-Fa-f]{32})\b", line)
                if re.search(r"SHA-?1\b", u):
                    cands["sha1"] += re.findall(r"\b([0-9A-Fa-f]{40})\b", line)
        ok_md5 = d["md5"] in [c.lower() for c in cands["md5"]]
        ok_sha1 = d["sha1"] in [c.lower() for c in cands["sha1"]]
        self.R["integrity"] = {"record": src, "md5_match": ok_md5, "sha1_match": ok_sha1}
        self.log("MD5 %s   %s" % (d["md5"], "MATCH" if ok_md5 else "NO MATCH"))
        self.log("SHA-1 %s %s" % (d["sha1"], "MATCH" if ok_sha1 else "NO MATCH"))
        self.log("SHA-256 %s" % d["sha256"])
        if not (ok_md5 or ok_sha1):
            self.decide("R1", "no hash of the evidence matches the acquisition record", "STOP", "analysis aborted")
            self.find("HIGH", "Integrity", "The evidence does not match its acquisition record", src or "image_info.txt")
            return False
        self.decide("R1", "hashes checked", "CONTINUE", "MD5 %s, SHA-1 %s" % ("match" if ok_md5 else "no match", "match" if ok_sha1 else "no match"))
        return True

    # ---------------------------------------------------------------- preservation
    def preserve(self):
        self.log("ACT - hashing extracted copies, setting them read-only, creating working copies")
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
        for name in self.dbs:
            self.dbs[name]["sha256"] = self.before.get(name)

    # ---------------------------------------------------------------- R2 duplicates
    def rule_duplicates(self):
        by_hash = {}
        for name, info in self.dbs.items():
            by_hash.setdefault(info["sha256"], []).append(name)
        n = 0
        for h, names in by_hash.items():
            if len(names) > 1:
                names.sort(key=lambda x: (not x.startswith("data/data/"), x))
                keep = names[0]
                for other in names[1:]:
                    self.dbs[other]["duplicate_of"] = keep
                    n += 1
        if n:
            self.decide("R2", "%d databases are byte-identical to another one" % n, "analyse one copy only",
                        "typically data/user/0/... = data/data/... (symbolic link)")

    # ---------------------------------------------------------------- generic analysis of every database
    def analyse_all(self):
        self.log("ACT - generic analysis of every unique database")
        for name, info in sorted(self.dbs.items()):
            if info.get("duplicate_of"):
                continue
            p = safe_join(self.work, name)
            try:
                con = connect_ro(p)
                ts = tables(con)
                rows = 0
                for t in ts:
                    c = q1(con, 'SELECT COUNT(*) FROM "%s"' % t.replace('"', '""'))
                    rows += c if isinstance(c, int) else 0
                info.update({"tables": len(ts), "rows": rows,
                             "page_count": q1(con, "PRAGMA page_count"), "page_size": q1(con, "PRAGMA page_size"),
                             "freelist": q1(con, "PRAGMA freelist_count") or 0})
                # R5 sqlite_sequence gaps
                if "sqlite_sequence" in ts:
                    gaps = {}
                    for t, seq in con.execute("SELECT name, seq FROM sqlite_sequence"):
                        if t in ts and "_id" in columns(con, t) and isinstance(seq, int) and seq <= 1_000_000:
                            ids = {r[0] for r in con.execute('SELECT _id FROM "%s"' % t)}
                            miss = sorted(set(range(1, seq + 1)) - ids)
                            if miss:
                                gaps[t] = {"seq": seq, "rows": len(ids), "missing": miss[:50], "missing_count": len(miss)}
                    info["sequence_gaps"] = gaps
                con.close()
            except sqlite3.Error as e:
                info["error"] = str(e)
                self.log("Cannot read %s: %s" % (name, e), "WARN")
        uniq = [n for n, i in self.dbs.items() if not i.get("duplicate_of")]
        self.log("Analysed %d unique databases (%d duplicates skipped)" % (len(uniq), len(self.dbs) - len(uniq)))

    # ---------------------------------------------------------------- R3 carve free pages
    def rule_free_pages(self):
        for name, info in sorted(self.dbs.items()):
            if info.get("duplicate_of") or not info.get("freelist"):
                continue
            p = safe_join(self.work, name)
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
                cnt = min(int.from_bytes(pg[4:8], "big"), (ps - 8) // 4)
                pages += [int.from_bytes(pg[8 + 4 * i:12 + 4 * i], "big") for i in range(cnt)]
                trunk = int.from_bytes(pg[0:4], "big")
            found = []
            for n in pages:
                found += strings_of(data[(n - 1) * ps:n * ps])
            found = list(dict.fromkeys(found))
            info["carved_free_page_strings"] = len(found)
            out = os.path.join(self.carved, name.replace("/", "__") + ".freepages.txt")
            open(out, "w", encoding="utf-8").write("\n".join(found))
            self.decide("R3", "%s has %d free pages" % (name, info["freelist"]), "carve free pages",
                        "%d text strings recovered -> %s" % (len(found), os.path.basename(out)))
            if found and name.split("/")[-1] in ("mmssms.db", "msgstore.db", "bugle_db", "accounts_ce.db", "sulogs.db"):
                self.find("HIGH", "Q4", "%d text fragments recovered from free (deleted) pages of %s, e.g. %s" %
                          (len(found), name.split("/")[-1], "; ".join(s[:40] for s in found[:3])), name)
        carved = sorted(((i.get("carved_free_page_strings") or 0, n) for n, i in self.dbs.items() if i.get("carved_free_page_strings")), reverse=True)
        if carved:
            self.find("MEDIUM", "Q4", "Free (deleted) pages with readable text in %d databases; most: %s" %
                      (len(carved), ", ".join("%s (%d)" % (n.split("/")[-1], c) for c, n in carved[:5])), "carved/*.freepages.txt")

    # ---------------------------------------------------------------- R4 WAL
    def rule_wal(self):
        for name, info in sorted(self.dbs.items()):
            wal = name + "-wal"
            if info.get("duplicate_of") or wal not in info.get("companions", []):
                continue
            wp = safe_join(self.work, wal)
            size = os.path.getsize(wp)
            if size <= 32:
                continue
            w = open(wp, "rb").read()
            magic = int.from_bytes(w[0:4], "big")
            if magic not in (0x377F0682, 0x377F0683):
                continue
            ps = int.from_bytes(w[8:12], "big")
            frames = (size - 32) // (24 + ps) if ps else 0
            mp = safe_join(self.work, name)
            db_strings = set(strings_of(open(mp, "rb").read())) if os.path.getsize(mp) < 100 * 1024 * 1024 else set()
            only = [s for s in dict.fromkeys(strings_of(w)) if s not in db_strings]
            out = os.path.join(self.carved, name.replace("/", "__") + ".wal_only.txt")
            open(out, "w", encoding="utf-8").write("\n".join(only))
            info["wal_frames"], info["wal_only_strings"] = frames, len(only)
            self.decide("R4", "%s has a WAL of %s bytes (%d frames)" % (name, format(size, ","), frames),
                        "read WAL frames, keep text absent from the main file",
                        "%d strings only in the WAL -> %s" % (len(only), os.path.basename(out)))
            if only and name.split("/")[-1] in ("mmssms.db", "msgstore.db", "bugle_db", "accounts_ce.db", "sulogs.db"):
                self.find("MEDIUM", "Q2/Q4", "%d text fragments exist only in the WAL of %s (recent changes not yet "
                          "written to the database, or older page versions)" % (len(only), name.split("/")[-1]), wal)
        wals = sorted(((i.get("wal_only_strings") or 0, n) for n, i in self.dbs.items() if i.get("wal_only_strings")), reverse=True)
        if wals:
            self.find("INFO", "Q4", "WAL files with text absent from their database: %d databases; most: %s" %
                      (len(wals), ", ".join("%s (%d)" % (n.split("/")[-1], c) for c, n in wals[:5])), "carved/*.wal_only.txt")

    # ---------------------------------------------------------------- R5 deletion traces
    def rule_deletions(self):
        for name, info in sorted(self.dbs.items()):
            for t, g in (info.get("sequence_gaps") or {}).items():
                self.decide("R5", "%s table %s: highest id %s, %s rows" % (name.split("/")[-1], t, g["seq"], g["rows"]),
                            "flag deleted rows", "missing ids %s%s" % (g["missing"][:10], " ..." if g["missing_count"] > 10 else ""))
                if name.endswith("mmssms.db") or name.endswith("msgstore.db"):
                    self.find("HIGH", "Q4", "%d row(s) of table %s were created then deleted (ids %s)" %
                              (g["missing_count"], t, g["missing"][:10]), name)

    # ---------------------------------------------------------------- R6 encrypted databases
    def rule_encrypted_dbs(self):
        if not self.no_sig_db:
            return
        self.decide("R6", "%d files named .db have no SQLite signature" % len(self.no_sig_db), "flag as probably encrypted",
                    ", ".join(x["path"].split("/")[-1] for x in self.no_sig_db[:8]) + (" ..." if len(self.no_sig_db) > 8 else ""))
        apps = set()
        for x in self.no_sig_db:
            mm = re.match(r"data/(?:data|user/0|user_de/0)/([^/]+)/", x["path"])
            apps.add(mm.group(1) if mm else "other")
        apps = sorted(apps)
        self.find("MEDIUM", "Limitation", "%d databases are probably encrypted (no SQLite signature), in: %s" %
                  (len(self.no_sig_db), ", ".join(a for a in apps if a)[:300]), "signature check")

    # ---------------------------------------------------------------- R7 WhatsApp backup
    def rule_whatsapp_backup(self):
        key = next((p for n, p in self.other_files.items() if n.endswith("com.whatsapp/files/key")), None)
        backups = [(n, p) for n, p in self.other_files.items() if ".crypt1" in n]
        if not (key and backups):
            return
        try:
            from Crypto.Cipher import AES  # pycryptodome
        except ImportError:
            self.decide("R7", "WhatsApp key and %d backup(s) present" % len(backups), "decrypt backup",
                        "SKIPPED: install the library with 'pip install pycryptodome' and run again")
            self.find("MEDIUM", "Encrypted data", "WhatsApp key and encrypted backup present: the backup can be decrypted", backups[0][0])
            return
        k = open(key, "rb").read()
        for n, p in backups:
            if not n.endswith(".crypt12"):
                self.decide("R7", "%s present" % n, "decrypt", "SKIPPED: only crypt12 is implemented")
                continue
            data = open(p, "rb").read()
            try:
                plain = AES.new(k[126:158], AES.MODE_GCM, nonce=data[51:67]).decrypt(data[67:-20])
                db = zlib.decompress(plain)
            except Exception as e:  # wrong key / format
                self.decide("R7", "%s present with key" % n, "decrypt", "FAILED (%s)" % e)
                continue
            if db[:16] != SQLITE_MAGIC:
                self.decide("R7", "%s present with key" % n, "decrypt", "FAILED: output is not SQLite")
                continue
            out = os.path.join(self.run, "decrypted", "msgstore_backup.db")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            open(out, "wb").write(db)
            r = analyse_whatsapp(out)
            live = self.R.get("whatsapp", {}).get("rows")
            res = "decrypted backup = valid SQLite (%s bytes, SHA-256 %s…); %s messages vs %s in the live database" % (
                format(len(db), ","), sha256_file(out)[:16], r.get("rows") if r.get("rows") is not None else "no", live)
            self.decide("R7", "WhatsApp key file and %s present" % n, "decrypt with AES-GCM, verify signature, compare", res)
            self.R["whatsapp_backup"] = {"source": n, "sha256": sha256_file(out), **r}
            self.find("HIGH", "Encrypted data", "WhatsApp backup %s decrypted into a readable SQLite database: %s (live database: %s messages)" %
                      (n.split("/")[-1], ("%s messages" % r["rows"]) if r.get("rows") is not None else "no messages table", live), n)

    # ---------------------------------------------------------------- R8 privacy apps
    def rule_privacy_apps(self):
        for pkg, label in PRIVACY_APPS.items():
            if pkg in self.app_dirs:
                dbs = [n.split("/")[-1] for n, i in self.dbs.items() if "/%s/" % pkg in n and not i.get("duplicate_of")]
                self.decide("R8", "app folder data/data/%s present" % pkg, "flag app, list its databases",
                            "%s; databases: %s" % (label, ", ".join(dbs) or "none readable"))
                self.find("MEDIUM", "Q4/Q6", "%s installed (%s)" % (label, pkg), "data/data/%s" % pkg)

    # ---------------------------------------------------------------- R9 specialised analyses
    def rule_known_dbs(self):
        w = lambda n: safe_join(self.work, n)
        for name, info in sorted(self.dbs.items()):
            if info.get("duplicate_of"):
                continue
            base = name.split("/")[-1]
            if base == "mmssms.db":
                r = analyse_mmssms(w(name))
                self.R.setdefault("mmssms", {})[name] = r
                self.decide("R9", "SMS database found: %s" % name, "SMS/MMS analysis",
                            "%s SMS, %s MMS, %s orphan part(s)" % (r["sms"], r["mms"], len(r["orphan_parts"])))
                if r["sms"]:
                    self.find("INFO", "Q2", "%s SMS from %s to %s UTC in %s" % (r["sms"], r["first_utc"], r["last_utc"], name), name)
                for o in r["orphan_parts"]:
                    self.find("MEDIUM", "Q4", "Orphan MMS part %s (mid %s) pointing to %s" % (o.get("_id"), o.get("mid"), o.get("_data")), name)
            elif base == "msgstore.db":
                r = analyse_whatsapp(w(name))
                self.R["whatsapp"] = r
                self.decide("R9", "WhatsApp database found", "message types and locations",
                            "%s rows, %d location messages" % (r.get("rows"), len(r.get("locations", []))))
                if r.get("locations"):
                    caps = [x["caption"] for x in r["locations"] if x.get("caption")]
                    self.find("HIGH", "Q2/Q5", "%d WhatsApp location messages on %s (local), all within %s m, captions %s" %
                              (len(r["locations"]), r["locations"][0]["local"][:10], r.get("max_distance_m"), caps), name)
            elif base == "accounts_ce.db":
                r = analyse_accounts(w(name))
                self.R["accounts"] = r
                self.decide("R9", "accounts database found", "list accounts (password column not read)", "%d accounts" % r["count"])
                google = [a["name"] for a in r["accounts"] if a["type"] == "com.google"]
                self.find("INFO", "Q1", "%d accounts; Google account(s): %s" % (r["count"], ", ".join(google)), name)
            elif base == "sulogs.db":
                r = analyse_magisk(w(name))
                self.R["magisk"] = r
                self.decide("R9", "Magisk root log found", "list root requests", "%s requests, first %s, last %s" % (r["count"], r["first"], r["last"]))
                if r["count"]:
                    self.find("HIGH", "Q1/Q4", "Device rooted: %s root requests logged by Magisk, first %s UTC, last %s UTC" %
                              (r["count"], r["first"], r["last"]), name)

    # ---------------------------------------------------------------- R10 ALEAPP comparison
    def rule_aleapp(self):
        d = self.a.aleapp_tsv
        if not d or not os.path.isdir(d):
            self.log("ALEAPP TSV folder not found (%s): R10 not triggered" % d, "WARN")
            return
        cmp = []
        active = next((v for k, v in self.R.get("mmssms", {}).items() if v.get("sms")), None)

        def add(check, a, b, note=""):
            cmp.append({"check": check, "aleapp": a, "agent": b, "match": "YES" if str(a) == str(b) else "NO", "note": note})

        for fn, key, label in (("SMS Messages.tsv", "sms", "SMS"), ("MMS Messages.tsv", "mms", "MMS")):
            if os.path.isfile(os.path.join(d, fn)) and active:
                add(label, len(read_tsv(os.path.join(d, fn))[1]), active[key])
        if os.path.isfile(os.path.join(d, "Accounts_ce.tsv")) and "accounts" in self.R:
            add("Accounts", len(read_tsv(os.path.join(d, "Accounts_ce.tsv"))[1]), self.R["accounts"]["count"])
        f = os.path.join(d, "WhatsApp - Messages.tsv")
        if os.path.isfile(f) and "whatsapp" in self.R:
            head, rows = read_tsv(f)
            wr = self.R["whatsapp"].get("rows")
            add("WhatsApp messages", len(rows), wr - 1 if isinstance(wr, int) else wr, "agent excludes internal row _id 1")
            mi = head.index("Message") if "Message" in head else None
            ai = head.index("Attachment") if "Attachment" in head else None
            empty = [r for r in rows if mi is not None and not r[mi].strip() and (ai is None or not r[ai].strip())]
            times = {x["utc"] for x in self.R["whatsapp"].get("locations", [])}
            ex = [r for r in empty if r[0][:19] in times]
            cmp.append({"check": "WhatsApp rows empty in ALEAPP", "aleapp": len(empty),
                        "agent": "%d are location messages" % len(ex), "match": "EXPLAINED", "note": "matched by timestamp"})
        self.R["comparison"] = cmp
        diff = [c for c in cmp if c["match"] == "NO"]
        self.decide("R10", "ALEAPP TSV exports found", "compare counts",
                    "%d checks, %d identical, %d different, %d explained" %
                    (len(cmp), sum(c["match"] == "YES" for c in cmp), len(diff), sum(c["match"] == "EXPLAINED" for c in cmp)))
        for c in diff:
            self.find("MEDIUM", "Validation", "ALEAPP and agent differ on %s (%s vs %s)" % (c["check"], c["aleapp"], c["agent"]), "ALEAPP TSV")

    # ---------------------------------------------------------------- re-verification
    def reverify(self):
        after = {}
        for d, _, fs in os.walk(self.ext):
            for fn in fs:
                p = os.path.join(d, fn)
                after[os.path.relpath(p, self.ext).replace("\\", "/")] = sha256_file(p)
        same = after == self.before
        changed = []
        for k, h in self.before.items():
            wp = safe_join(self.work, k)
            if os.path.isfile(wp) and sha256_file(wp) != h:
                changed.append(k)
        self.R["reverify"] = {"files": len(after), "extracted_identical": same, "working_changed": changed}
        self.log("RE-VERIFY - %d extracted files: %s; working copies changed by SQLite: %s" %
                 (len(after), "IDENTICAL" if same else "DIFFERENT", changed[:5] or "none"))

    # ---------------------------------------------------------------- loop
    def run_loop(self):
        self.log("Forensic triage agent v%s - Python %s - output %s" % (VERSION, self.R["python"], self.run))
        for r in RULES:
            self.log("%s: IF %s THEN %s" % r, "RULE")
        self.observe_evidence()
        if not self.rule_integrity():
            return
        self.preserve()
        self.rule_duplicates()
        self.analyse_all()
        for step in (self.rule_known_dbs, self.rule_deletions, self.rule_free_pages, self.rule_wal,
                     self.rule_encrypted_dbs, self.rule_whatsapp_backup, self.rule_privacy_apps, self.rule_aleapp):
            step()
        self.reverify()

    def finish(self):
        self.R["finished"] = dt.datetime.now().isoformat(timespec="seconds")
        self.R["decisions"], self.R["findings"] = self.decisions, self.findings
        self.R["databases"] = self.dbs
        self.R["encrypted_db_candidates"] = self.no_sig_db
        json.dump(self.R, open(os.path.join(self.run, "results.json"), "w", encoding="utf-8"), indent=2, default=str)
        with open(os.path.join(self.run, "databases.csv"), "w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(["path", "size", "sha256", "duplicate_of", "tables", "rows", "pages", "free_pages", "wal_frames", "deleted_rows"])
            for n, i in sorted(self.dbs.items()):
                wr.writerow([n, i.get("size"), i.get("sha256"), i.get("duplicate_of", ""), i.get("tables"), i.get("rows"),
                             i.get("page_count"), i.get("freelist"), i.get("wal_frames", ""),
                             sum(g["missing_count"] for g in (i.get("sequence_gaps") or {}).values())])
        write_html(os.path.join(self.run, "report.html"), self)
        self.log("DONE - %d decisions, %d findings - report: %s" % (len(self.decisions), len(self.findings),
                                                                       os.path.join(self.run, "report.html")))
        self.log.close()


# ======================================================================= specialised analyses (knowledge)
def analyse_mmssms(p):
    con = connect_ro(p)
    ts = tables(con)
    r = {"sms": q1(con, "SELECT COUNT(*) FROM sms") if "sms" in ts else 0,
         "mms": q1(con, "SELECT COUNT(*) FROM pdu") if "pdu" in ts else 0, "orphan_parts": []}
    if r["sms"]:
        r["first_utc"] = utc(q1(con, "SELECT MIN(date) FROM sms"))
        r["last_utc"] = utc(q1(con, "SELECT MAX(date) FROM sms"))
    if "part" in ts and "pdu" in ts:
        cols = [c for c in ("_id", "mid", "ct", "cl", "_data") if c in columns(con, "part")]
        for row in con.execute("SELECT %s FROM part WHERE mid NOT IN (SELECT _id FROM pdu)" % ", ".join(cols)):
            r["orphan_parts"].append(dict(zip(cols, row)))
    con.close()
    return r


def analyse_whatsapp(p):
    con = connect_ro(p)
    ts = tables(con)
    r = {"rows": q1(con, "SELECT COUNT(*) FROM messages") if "messages" in ts else None,
         "revoked": q1(con, "SELECT COUNT(*) FROM message_revoked") if "message_revoked" in ts else None, "locations": []}
    if "messages" in ts:
        cols = columns(con, "messages")
        want = [c for c in ("_id", "key_from_me", "timestamp", "media_wa_type", "latitude", "longitude", "media_caption") if c in cols]
        if "media_wa_type" in want:
            pts = []
            for row in con.execute("SELECT %s FROM messages WHERE CAST(media_wa_type AS INTEGER) IN (5,16) ORDER BY timestamp" % ", ".join(want)):
                d = dict(zip(want, row))
                pts.append((d.get("latitude"), d.get("longitude")))
                r["locations"].append({"id": d.get("_id"), "direction": "Sent" if str(d.get("key_from_me")) == "1" else "Received",
                                       "utc": utc(d.get("timestamp")), "local": local(d.get("timestamp")),
                                       "type": "Location" if str(d.get("media_wa_type")) == "5" else "Live location",
                                       "lat": round(d["latitude"], 2) if d.get("latitude") is not None else None,
                                       "lon": round(d["longitude"], 2) if d.get("longitude") is not None else None,
                                       "caption": d.get("media_caption")})
            pts = [x for x in pts if x[0] is not None and x[1] is not None]
            if len(pts) > 1:
                def dist(a, b):
                    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
                    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
                    return 2 * 6371000 * math.asin(math.sqrt(h))
                r["max_distance_m"] = round(max(dist(a, b) for i, a in enumerate(pts) for b in pts[i + 1:]), 1)
    con.close()
    return r


def analyse_accounts(p):
    con = connect_ro(p)
    rows = con.execute("SELECT _id, name, type FROM accounts ORDER BY _id").fetchall()
    con.close()
    return {"count": len(rows), "accounts": [{"id": a, "name": b, "type": c} for a, b, c in rows]}


def analyse_magisk(p):
    con = connect_ro(p)
    ts = tables(con)
    r = {"count": 0, "first": "", "last": ""}
    if "logs" in ts:
        cols = columns(con, "logs")
        r["count"] = q1(con, "SELECT COUNT(*) FROM logs")
        if "time" in cols:
            r["first"] = utc(q1(con, "SELECT MIN(time) FROM logs"))
            r["last"] = utc(q1(con, "SELECT MAX(time) FROM logs"))
    con.close()
    return r


# ======================================================================= HTML report
def write_html(path, ag):
    e = lambda x: html.escape(str(x))
    R = ag.R
    t = R.get("tar", {})
    i = R.get("integrity", {})
    col = {"HIGH": "#c62828", "MEDIUM": "#b26a00", "INFO": "#1d4e89"}
    h = ['<!doctype html><html><head><meta charset="utf-8"><title>Forensic triage agent</title><style>'
         'body{font-family:Segoe UI,Arial,sans-serif;max-width:1050px;margin:24px auto;padding:0 16px;color:#1f2933}'
         'table{border-collapse:collapse;width:100%;margin:8px 0 18px}td,th{border:1px solid #c9d1d9;padding:5px 7px;font-size:13px;'
         'text-align:left;vertical-align:top}th{background:#e8eef5}h1,h2{color:#1d4e89}h2{border-bottom:1px solid #c9d1d9;padding-bottom:3px}'
         'code{font-size:12px}.box{background:#f3f6f9;border-left:4px solid #1d4e89;padding:8px 12px}</style></head><body>',
         "<h1>Forensic triage agent — report</h1>",
         "<p>Agent v%s · %s → %s · times in UTC unless “local” (UTC−4)</p>" % (e(VERSION), e(R.get("started")), e(R.get("finished"))),
         '<div class="box"><b>How the agent works:</b> OBSERVE the evidence (every SQLite database found by its signature) → '
         'DECIDE with rules R1–R10 → ACT (run the chosen analysis) → RECORD every step in <code>agent_log.txt</code>.</div>',
         "<h2>1. Evidence and integrity</h2><table>",
         "<tr><th>Evidence</th><td><code>%s</code> — %s bytes</td></tr>" % (e(t.get("path")), format(t.get("size", 0), ",")),
         "<tr><th>MD5</th><td><code>%s</code> — %s</td></tr>" % (e(t.get("md5")), "MATCH" if i.get("md5_match") else "no match"),
         "<tr><th>SHA-1</th><td><code>%s</code> — %s</td></tr>" % (e(t.get("sha1")), "MATCH" if i.get("sha1_match") else "no match"),
         "<tr><th>SHA-256</th><td><code>%s</code></td></tr>" % e(t.get("sha256")),
         "<tr><th>Observed</th><td>%s entries; %d SQLite databases found by signature (%d unique); %d .db files without signature; %d app folders</td></tr></table>" %
         (format(ag.index_count, ","), len(ag.dbs), sum(1 for x in ag.dbs.values() if not x.get("duplicate_of")), len(ag.no_sig_db), len(ag.app_dirs)),
         "<h2>2. Findings</h2><table><tr><th>Severity</th><th>Question</th><th>Finding</th><th>Source</th></tr>"]
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    for f in sorted(ag.findings, key=lambda x: order.get(x["severity"], 3)):
        h.append('<tr><td><b style="color:%s">%s</b></td><td>%s</td><td>%s</td><td><code>%s</code></td></tr>' %
                 (col.get(f["severity"], "#333"), e(f["severity"]), e(f["question"]), e(f["finding"]), e(f["source"])))
    h.append("</table><h2>3. Decisions taken by the agent</h2><table><tr><th>Rule</th><th>Trigger (observed)</th><th>Action</th><th>Result</th></tr>")
    for d in ag.decisions:
        h.append("<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>" % tuple(e(d[k]) for k in ("rule", "trigger", "action", "result")))
    h.append("</table><h2>4. Rules</h2><table><tr><th>Rule</th><th>IF</th><th>THEN</th></tr>")
    for r in RULES:
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % tuple(e(x) for x in r))
    wa = R.get("whatsapp", {})
    if wa.get("locations"):
        h.append("</table><h2>5. WhatsApp locations</h2><table><tr><th>_id</th><th>Local</th><th>Direction</th><th>Type</th><th>Lat</th><th>Lon</th><th>Caption</th></tr>")
        for x in wa["locations"]:
            h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                     tuple(e(x.get(k) if x.get(k) is not None else "") for k in ("id", "local", "direction", "type", "lat", "lon", "caption")))
    h.append("</table><h2>6. Comparison with ALEAPP</h2><table><tr><th>Check</th><th>ALEAPP</th><th>Agent</th><th>Match</th><th>Note</th></tr>")
    for c in R.get("comparison", []):
        h.append("<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td>%s</td></tr>" % tuple(e(c[k]) for k in ("check", "aleapp", "agent", "match", "note")))
    big = sorted((x for x in ag.dbs.items() if not x[1].get("duplicate_of")), key=lambda x: -(x[1].get("rows") or 0))[:25]
    h.append("</table><h2>7. Largest databases (top 25 by rows — full list in databases.csv)</h2><table>"
             "<tr><th>Database</th><th>Tables</th><th>Rows</th><th>Free pages</th><th>WAL frames</th></tr>")
    for n, x in big:
        h.append("<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %
                 (e(n), e(x.get("tables")), e(x.get("rows")), e(x.get("freelist")), e(x.get("wal_frames", ""))))
    rv = R.get("reverify", {})
    h.append("</table><h2>8. Re-verification</h2><p>%s extracted files: <b>%s</b> before and after. Working copies changed by SQLite: %s.</p>" %
             (e(rv.get("files")), "IDENTICAL" if rv.get("extracted_identical") else "DIFFERENT", e(rv.get("working_changed") or "none")))
    h.append("<p>Files: <code>agent_log.txt</code> (every step), <code>results.json</code>, <code>databases.csv</code>, "
             "<code>carved/</code> (recovered text).</p></body></html>")
    open(path, "w", encoding="utf-8").write("\n".join(h))


def main():
    ap = argparse.ArgumentParser(description="Forensic triage agent for an Android file-system extraction (.tar)")
    ap.add_argument("--tar", default=DEFAULT_TAR)
    ap.add_argument("--image-info", default=DEFAULT_IMAGE_INFO)
    ap.add_argument("--aleapp-tsv", default=DEFAULT_ALEAPP_TSV)
    ap.add_argument("--out", default=DEFAULT_OUT)
    ag = Agent(ap.parse_args())
    try:
        ag.run_loop()
    finally:
        ag.finish()


if __name__ == "__main__":
    main()
