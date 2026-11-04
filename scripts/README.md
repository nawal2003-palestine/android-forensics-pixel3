# Scripts — verification script and agents

Python 3.10+. Run each script with `--help` to see every option.

| Script | Role |
|---|---|
| `forensic_agent.py` (v1) | Repeats the manual procedure: hashes the tar against the acquisition record, extracts the key databases, runs the SQL checks, compares with the ALEAPP TSV export, writes `report.html` / JSON |
| `forensic_agent_v2.py` (v2) | Rule-based agent (observe → decide → act → record), 10 rules: hash mismatch stops, WAL-only text, freelist carving, `sqlite_sequence` gaps, encrypted databases, WhatsApp `.crypt12` decryption |
| `forensic_agent_v3.py` (v3) | Generic gap explorer: finds databases the tool never read and ranks them by generic signals (timestamps, phone numbers, coordinates, gaps) → `proposals.csv`, `queries_for_db_browser.sql`, `report.html` |

## Requirements
- v1 and v3: Python standard library only.
- v2: `pip install pycryptodome` (for `.crypt12` decryption).

## Examples (Windows)
```
python forensic_agent.py    --tar "D:\Evidence\Data.tar" --out "C:\Case\Agent"
python forensic_agent_v2.py --tar "D:\Evidence\Data.tar" --aleapp-tsv "D:\ALEAPP_Output\_TSV Exports" --out "C:\Case\Agent"
python forensic_agent_v3.py --evidence "D:\Evidence\Data.tar" --tool-report "D:\ALEAPP_Output" --out "C:\Case\Agent"
```

The scripts only **read** the evidence: they work on extracted copies and re-hash the evidence at the end.
Their output is a list of leads for the examiner, not findings — every lead must be checked manually.

> The evidence image is not included. It is available from Digital Corpora (*Android 11* image).
