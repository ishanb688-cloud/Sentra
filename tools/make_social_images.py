"""Regenerates web/og.png (link preview) and docs/img/github-social.png from the site's own
fonts and emblem. Needs: pip install playwright && playwright install chromium"""
import re
import shutil
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
fonts = re.search(r'<style id="fonts">(.*?)</style>', html, re.S).group(1)
logo = (ROOT / "web" / "logo.svg").read_text().replace('viewBox="-3 -1 126 66"', 'viewBox="-3 -1 126 66" width="540" height="283"', 1)


def page(w, h):
    return f'''<html><head><style>{fonts}
*{{margin:0;box-sizing:border-box}}body{{width:{w}px;height:{h}px;background:radial-gradient(900px 600px at 18% 30%,rgba(155,123,255,.28),transparent 62%),radial-gradient(700px 500px at 95% 100%,rgba(155,123,255,.14),transparent 60%),#09090b;color:#f3efe6;font-family:Inter,sans-serif;display:flex;align-items:center;padding:0 60px;gap:30px;overflow:hidden}}
.l svg{{filter:drop-shadow(0 0 40px rgba(155,123,255,.55))}}
.t h1{{font-family:"Instrument Serif",serif;font-weight:400;font-size:138px;line-height:.95;letter-spacing:-.03em;background:linear-gradient(100deg,#ece5ff,#9b7bff 70%);-webkit-background-clip:text;color:transparent}}
.t p{{font-family:"Instrument Serif",serif;font-size:50px;margin-top:18px;line-height:1.1}}.t p i{{color:#b9a3ff}}
.c{{display:flex;gap:12px;margin-top:30px;flex-wrap:wrap}}.c span{{border:1px solid rgba(255,255,255,.18);border-radius:999px;padding:9px 18px;font-size:22px;color:#cfc9dc}}
.f{{position:absolute;bottom:34px;left:60px;font-size:20px;color:#8a8696;letter-spacing:.04em}}
</style></head><body><div class="l">{logo}</div><div class="t"><h1>Sentra</h1><p>One check for every <i>scam signal.</i></p><div class="c"><span>Messages</span><span>Links</span><span>QR and UPI</span><span>App files</span></div></div><div class="f">Rule-based and explainable &nbsp;·&nbsp; Never visits your links &nbsp;·&nbsp; Never runs your apps</div></body></html>'''


with sync_playwright() as p:
    b = p.chromium.launch()
    for w, h, out in [(1200, 630, ROOT / "web" / "og.png"), (1280, 640, ROOT / "docs" / "img" / "github-social.png")]:
        pg = b.new_page(viewport={"width": w, "height": h})
        pg.set_content(page(w, h))
        pg.wait_for_timeout(600)
        pg.screenshot(path=str(out))
        pg.close()
    b.close()
shutil.copy(ROOT / "docs" / "img" / "github-social.png", ROOT / "docs" / "img" / "banner.png")
print("images written")
