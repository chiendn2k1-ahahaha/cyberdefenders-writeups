"""Build the static writeup site: src/*.md -> docs/*.html (GitHub Pages serves /docs).

Lab pages: src/labs/<slug>.md, slug must match a CyberDefenders lab slug in data/labs_meta.json.
Front matter (first lines until a blank line):
    title: LockBit
    summary: one line
"""
import datetime
import hashlib
import html
import json
import pathlib
import re
import subprocess

import markdown

ROOT = pathlib.Path(__file__).parent
SRC = ROOT / "src"
OUT = ROOT / "docs"
META = ROOT / "data" / "labs_meta.json"
DIFF_ORDER = {"insane": 0, "hard": 1, "medium": 2, "easy": 3}
SITE = "https://chiendn2k1-ahahaha.github.io/cyberdefenders-writeups/"
AUTHOR = {"@type": "Person", "name": "Chiendn2k1", "url": "https://cyberdefenders.org/p/Chiendn2k1/"}
INDEX_TITLE = "CyberDefenders writeups tiếng Việt: Blue Team, DFIR, Threat Intel | Chiendn2k1"
INDEX_DESC = ("Writeup và walkthrough tiếng Việt cho các lab Blue Team trên CyberDefenders: network forensics, "
              "memory forensics, endpoint forensics, threat intel, malware analysis. Có ảnh công cụ thật, không ghi đáp án.")

# Inline guard (allowed by its CSP hash): content stays hidden until protect.js marks the page (class "pv"),
# and is hidden again when protect.js reports DevTools or tampering (class "dt").
# Blocking style.css/protect.js, disabling JavaScript or loading offline without them leaves the page blank.
GUARD_CSS = ("html:not(.pv) body>*:not(noscript),html.dt body>*{display:none!important}"
             "html.dt body::before{content:\"Đóng DevTools hoặc tải lại trang để xem nội dung.\";display:block;"
             "padding:48px 16px;text-align:center;font:18px/1.5 system-ui,sans-serif}")
GUARD_HASH = "sha256-" + __import__("base64").b64encode(hashlib.sha256(GUARD_CSS.encode("utf-8")).digest()).decode()

TEMPLATE = """<!doctype html>
<html lang="vi" translate="no" class="notranslate">
<head>
<meta charset="utf-8">
<meta name="google" content="notranslate">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self' '{guard_hash}'; img-src 'self' https://avatars.githubusercontent.com; script-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<style>{guard_css}</style>
<title>{title}</title>
<meta name="description" content="{desc}">
<meta name="author" content="Chiendn2k1">
<link rel="canonical" href="{canon}">
<meta property="og:type" content="{ogtype}">
<meta property="og:site_name" content="CyberDefenders writeups">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:url" content="{canon}">
<meta property="og:locale" content="vi_VN">
<script type="application/ld+json">{jsonld}</script>
<link rel="icon" href="{base}favicon.ico" sizes="any">
<link rel="icon" type="image/png" href="{base}assets/favicon-32.png">
<link rel="apple-touch-icon" href="{base}assets/apple-touch-icon.png">
<link rel="stylesheet" href="{base}style.css?v={ver}">
<script src="{base}protect.js?v={pver}"></script>
</head>
<body>
<noscript>Trang cần bật JavaScript để hiển thị nội dung.</noscript>
<header class="top"><a class="brand" href="{home}">CyberDefenders writeups</a>
<nav class="me">
<a href="https://www.linkedin.com/in/chiendn/" rel="noopener noreferrer" target="_blank">LinkedIn</a>
<a href="https://github.com/chiendn2k1-ahahaha" rel="noopener noreferrer" target="_blank">GitHub</a>
<a href="https://cyberdefenders.org/blueteam-ctf-challenges/leaderboard/" rel="noopener noreferrer" target="_blank">Bảng xếp hạng</a>
<a class="ava" href="https://cyberdefenders.org/p/Chiendn2k1/" rel="noopener noreferrer" target="_blank" title="Chiendn2k1 trên CyberDefenders"><img src="https://avatars.githubusercontent.com/u/352285299?s=80" alt="Avatar Chiendn2k1" width="36" height="36"></a>
</nav></header>
<main class="page{wide}">
{toc}
<article>
{body}
</article>
</main>
{scripts}
</body>
</html>
"""


def ver(name):
    return hashlib.sha1((OUT / name).read_bytes()).hexdigest()[:8]


def parse(text):
    meta = {}
    head, _, body = text.partition("\n\n")
    if head and all(re.match(r"^\w+:", line) for line in head.splitlines()):
        for line in head.splitlines():
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    else:
        body = text
    return meta, body


def jsonld(obj):
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


def page(meta, body_md, base, toc_on=True, wide=False, scripts="", seo=None):
    md = markdown.Markdown(extensions=["tables", "fenced_code", "toc", "attr_list", "md_in_html"],
                           extension_configs={"toc": {"toc_depth": "2-2"}})
    content = md.convert(body_md)
    toc = ""
    if toc_on and md.toc_tokens:
        items = "".join(f'<li><a href="#{t["id"]}">{html.escape(t["name"])}</a></li>'
                        for t in md.toc_tokens)
        toc = '<nav class="toc"><b>Mục lục</b><ul>' + items + "</ul></nav>"
    seo = seo or {}
    return TEMPLATE.format(title=html.escape(seo.get("title") or meta.get("title", "Writeup")), base=base,
                           home=base or "./", desc=html.escape(seo.get("desc", "")),
                           canon=seo.get("canon", SITE), ogtype=seo.get("ogtype", "website"),
                           jsonld=jsonld(seo.get("ld", {})),
                           ver=ver("style.css"), pver=ver("protect.js"), guard_css=GUARD_CSS, guard_hash=GUARD_HASH, toc=toc, body=content,
                           wide=" wide" if wide else "", scripts=scripts)


def lastmod(path):
    """Date of the last git commit touching path, else file mtime (YYYY-MM-DD)."""
    try:
        out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", str(path)], cwd=ROOT,
                             capture_output=True, text=True, timeout=20).stdout.strip()
        if out:
            return out
    except (OSError, subprocess.SubprocessError):
        pass
    return datetime.date.fromtimestamp(path.stat().st_mtime).isoformat()


def render_lab(slug, text, lab, modified):
    meta, body = parse(text)
    name = lab["name"]
    url = f"{SITE}labs/{slug}.html"
    desc = meta.get("summary", "")
    seo = {
        "title": f"{name} lab - CyberDefenders writeup tiếng Việt | Chiendn2k1",
        "desc": f"CyberDefenders {name} writeup (walkthrough tiếng Việt): {desc}",
        "canon": url, "ogtype": "article",
        "ld": {"@context": "https://schema.org", "@type": "TechArticle",
               "headline": f"{name} - CyberDefenders writeup", "description": desc,
               "inLanguage": "vi", "url": url, "dateModified": modified, "author": AUTHOR,
               "keywords": ", ".join(["CyberDefenders", name, "writeup", "walkthrough"]
                                     + lab["categories"] + lab["tools"]),
               "about": {"@type": "Thing", "name": f"CyberDefenders {name} lab",
                         "url": f"https://cyberdefenders.org/blueteam-ctf-challenges/{slug}/"}},
    }
    return meta, page(meta, body, "../", seo=seo)


def main():
    labs_meta = {m["slug"]: m for m in json.loads(META.read_text(encoding="utf-8"))}
    published = {}
    modified = {}
    (OUT / "labs").mkdir(parents=True, exist_ok=True)
    for p in sorted((SRC / "labs").glob("*.md")):
        if p.stem not in labs_meta:
            raise SystemExit(f"{p.name}: slug not in data/labs_meta.json")
        modified[p.stem] = lastmod(p)
        meta, out = render_lab(p.stem, p.read_text(encoding="utf-8"), labs_meta[p.stem], modified[p.stem])
        published[p.stem] = meta
        (OUT / "labs" / f"{p.stem}.html").write_text(out, encoding="utf-8")

    rows = []
    for slug, m in labs_meta.items():
        rows.append({
            "slug": slug, "name": m["name"], "categories": m["categories"],
            "difficulty": m["difficulty"], "questions": m["questions"],
            "objective": m.get("objective") or "", "tactics": m["tactics"], "tools": m["tools"],
            "writeup": f"labs/{slug}.html" if slug in published else "",
            "summary": published.get(slug, {}).get("summary", ""),
        })
    rows.sort(key=lambda r: (r["writeup"] == "", DIFF_ORDER.get(r["difficulty"], 9), r["name"].lower()))
    data = json.dumps(rows, ensure_ascii=False).replace("</", "<\\/")

    meta, body = parse((SRC / "index.md").read_text(encoding="utf-8"))
    body = body.replace("{{COUNT}}", str(len(published)))
    scripts = (f'<script type="application/json" id="labdata">{data}</script>\n'
               f'<script src="app.js?v={ver("app.js")}"></script>')
    # Static list of writeups inside #labapp: crawlers and no-JS readers get plain links;
    # app.js clears it and draws the interactive lab grid.
    items = []
    for r in rows:
        if not r["writeup"]:
            continue
        info = ", ".join(r["categories"] + [r["difficulty"].capitalize()])
        items.append(f'<li><a href="{r["writeup"]}">{html.escape(r["name"])} - CyberDefenders writeup</a>'
                     f' ({html.escape(info)}). {html.escape(r["summary"])}</li>')
    static = ('<h2>Danh sách writeup</h2>\n<ul class="seo-list">\n' + "\n".join(items) + "\n</ul>")
    seo = {"title": INDEX_TITLE, "desc": INDEX_DESC, "canon": SITE, "ogtype": "website",
           "ld": {"@context": "https://schema.org", "@type": "CollectionPage", "name": "CyberDefenders writeups",
                  "description": INDEX_DESC, "inLanguage": "vi", "url": SITE, "author": AUTHOR,
                  "hasPart": [{"@type": "TechArticle", "headline": f'{r["name"]} - CyberDefenders writeup',
                               "url": SITE + r["writeup"]} for r in rows if r["writeup"]]}}
    out = page(meta, body, "", toc_on=False, wide=True, scripts=scripts, seo=seo)
    out = out.replace("</article>", f'<div id="labapp">\n{static}\n</div>\n</article>', 1)
    (OUT / "index.html").write_text(out, encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")

    urls = [(SITE, max(modified.values(), default=datetime.date.today().isoformat()))]
    urls += [(f"{SITE}labs/{s}.html", modified[s]) for s in sorted(published)]
    sitemap = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    sitemap += [f"  <url><loc>{u}</loc><lastmod>{d}</lastmod></url>" for u, d in urls]
    sitemap.append("</urlset>")
    (OUT / "sitemap.xml").write_text("\n".join(sitemap) + "\n", encoding="utf-8")
    print(f"built {len(published)} writeup(s), {len(rows)} labs in index")


if __name__ == "__main__":
    main()
