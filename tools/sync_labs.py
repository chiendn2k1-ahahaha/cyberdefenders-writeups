"""Refresh data/labs_meta.json from the public CyberDefenders API (no login needed).

Keeps only labs that are retired AND listed in data/solved.txt.
Usage: python tools/sync_labs.py [--init-solved]
  --init-solved  write every lab slug currently on the platform to data/solved.txt
"""
import concurrent.futures as cf
import html
import json
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
META = ROOT / "data" / "labs_meta.json"
SOLVED = ROOT / "data" / "solved.txt"
BASE = "https://cyberdefenders.org"
UA = {"User-Agent": "Mozilla/5.0 (cyberdefenders-writeups sync)"}
TACTICS = {"Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
           "Privilege Escalation", "Defense Evasion", "Defense Impairment", "Credential Access",
           "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration",
           "Impact"}


def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def list_labs():
    labs, page = [], 1
    while True:
        try:
            data = json.loads(get(f"{BASE}/api/blueteam-ctf-challenges/?page={page}&size=30"))
        except Exception:
            break
        chunk = data.get("data", {}).get("labs", [])
        if not chunk:
            break
        labs += chunk
        page += 1
    return labs


def subjects(slug):
    page = get(f"{BASE}/blueteam-ctf-challenges/{slug}/")
    m = re.search(r'<meta name="description" content="[^"]*subjects: ([^"]*)\.">', page)
    return [html.unescape(s).strip() for s in m.group(1).split(", ")] if m else []


def main():
    labs = list_labs()
    if len(labs) < 100:
        raise SystemExit(f"only {len(labs)} labs returned, refusing to overwrite")
    if "--init-solved" in sys.argv:
        SOLVED.write_text("\n".join(sorted(l["slug"] for l in labs)) + "\n", encoding="utf-8")
    solved = set(SOLVED.read_text(encoding="utf-8").split())
    old = {m["slug"]: m for m in json.loads(META.read_text(encoding="utf-8"))} if META.exists() else {}
    keep = [l for l in labs if l.get("is_retired") and l["slug"] in solved]

    def build(l):
        prev = old.get(l["slug"])
        if prev and prev.get("tools") is not None:
            subj = prev["tactics"] + prev["tools"]
        else:
            subj = subjects(l["slug"])
        return {"slug": l["slug"], "name": l["name"], "categories": l.get("categories") or [],
                "difficulty": l.get("difficulty"), "questions": (old.get(l["slug"]) or {}).get("questions"),
                "objective": l.get("learning_objective") or "",
                "tactics": [s for s in subj if s in TACTICS],
                "tools": [s for s in subj if s not in TACTICS]}

    with cf.ThreadPoolExecutor(8) as ex:
        rows = list(ex.map(build, keep))
    for r in rows:
        if r["questions"] is None:
            r["questions"] = 0
    rows.sort(key=lambda r: r["slug"])
    META.write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    added = sorted(set(r["slug"] for r in rows) - set(old))
    print(f"labs on platform {len(labs)}, retired+solved {len(rows)}, new {added}")


if __name__ == "__main__":
    main()
