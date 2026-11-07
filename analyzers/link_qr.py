import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.fusion import make

DATA = Path(__file__).resolve().parent.parent / "data"
with open(DATA / "brands.json", encoding="utf-8") as f:
    BRANDS = json.load(f)

OFFICIAL = {d for b in BRANDS for d in b["domains"]}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co",
              "goo.gl", "shorturl.at", "tiny.cc", "ow.ly"}
BAD_TLDS = {"xyz", "top", "click", "work", "buzz", "icu", "rest", "gq", "tk",
            "ml", "cf", "ga", "monster", "cfd", "sbs", "cyou"}
TWO_LEVEL = {"co.in", "gov.in", "nic.in", "org.in", "net.in", "ac.in",
             "res.in", "co.uk", "com.au"}

LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"})
CRED_PATH = re.compile(r"(login|log-in|signin|sign-in|verify|verification|kyc|otp|password|passcode|secure|auth|update|account)", re.I)
RECEIVE = re.compile(r"\b(receive|received|credited|refund|cashback|prize|reward|you have won|claim|collect)\b", re.I)

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|shorturl\.at|tiny\.cc|ow\.ly)/[^\s<>\"']+"
    r"|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:xyz|top|click|work|buzz|icu|rest|cfd|sbs|cyou|apk)\b(?:/[^\s<>\"']*)?",
    re.I,
)
UPI_RE = re.compile(r"upi://pay\?[^\s<>\"']+", re.I)


def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def norm(s):
    return s.lower().translate(LEET).replace("rn", "m").replace("vv", "w")


def split_host(host):
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL:
        return ".".join(labels[-3:]), labels[:-3], labels[-1]
    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[:-2], labels[-1]
    return host, [], host


def brand_hits(tokens):
    hits = {}
    for b in BRANDS:
        for bt in b["tokens"]:
            for t in tokens:
                if t == bt:
                    kind = "embedded"
                elif t != bt and norm(t) == bt:
                    kind = "homoglyph"
                elif len(bt) >= 5 and len(t) >= 5 and lev(t, bt) <= (1 if len(bt) < 8 else 2):
                    kind = "typo"
                else:
                    continue
                prio = 1 if kind == "embedded" else 2
                if b["name"] not in hits or prio > hits[b["name"]][2]:
                    hits[b["name"]] = (kind, t, prio, b)
    return hits


def mentions(brand, ctx):
    return any(re.search(r"\b" + re.escape(t) + r"\b", ctx) for t in brand["tokens"])


def check_url(url, ctx, add):
    raw = url if re.match(r"^https?://", url, re.I) else "http://" + url
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return None
    if not host:
        return None

    https = raw.lower().startswith("https://")
    path_q = (p.path or "") + "?" + (p.query or "")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    reg, subs, tld = split_host(host)
    official = (not is_ip) and reg in OFFICIAL
    tricks = False

    if is_ip:
        add("link_odd_host", 1.0, f"raw IP address {host}")
        tricks = True
    if "@" in p.netloc:
        add("link_odd_host", 0.9, "'@' trick hides the real destination")
        tricks = True
    if port and port not in (80, 443):
        add("link_odd_host", 0.6, f"unusual port {port}")
    if len(subs) >= 4:
        add("link_odd_host", 0.5, "unusually deep subdomain chain")
    if any(l.startswith("xn--") for l in host.split(".")):
        add("link_punycode", 1.0, f"look-alike characters in {host}")
        tricks = True
    if host in SHORTENERS or reg in SHORTENERS:
        add("link_shortener", 1.0, host)
    if tld in BAD_TLDS:
        add("link_suspicious_tld", 1.0, "." + tld)
    if p.path.lower().endswith(".apk") or host.endswith(".apk"):
        add("link_apk_download", 1.0, "direct app-file download")

    brand_hit = False
    if not official and not is_ip and reg not in SHORTENERS:
        label = reg.split(".")[0]
        tokens = list({*re.split(r"[-_]", label), label.replace("-", "")})
        for name, (kind, tok, prio, b) in brand_hits(tokens).items():
            said = mentions(b, ctx)
            if kind == "embedded":
                add("link_lookalike_brand", 1.0 if said else 0.8,
                    f"{name} name inside unofficial domain {reg}")
            else:
                add("link_lookalike_brand", 1.0 if said else 0.9,
                    f"'{tok}' imitates {name}")
            brand_hit = True

        sub_tokens = [t for l in subs for t in re.split(r"[-_]", l)]
        for b in BRANDS:
            if any(t in b["tokens"] for t in sub_tokens):
                add("link_brand_in_subdomain", 1.0,
                    f"{b['name']} placed in front of unrelated domain {reg}")
                brand_hit = True

    if not official and CRED_PATH.search(path_q):
        add("link_credential_form", 0.8 if brand_hit else 0.6,
            "address looks like a login or verify page on an unofficial site")

    if official and not tricks:
        return (reg, https)
    return None


def check_upi(uri, ctx, add):
    q = parse_qs(urlparse(uri).query)
    pa = q.get("pa", [""])[0]
    pn = q.get("pn", [""])[0]
    payee = re.sub(r"[^a-z0-9]", "", (pn + pa).lower())

    if RECEIVE.search(ctx):
        add("qr_pay_not_receive", 1.0, "payment request, but the message talks about receiving money")
    for b in BRANDS:
        if mentions(b, ctx) and not any(t in payee for t in b["tokens"]):
            add("qr_payee_mismatch", 1.0, f"message mentions {b['name']} but the payee is {pn or pa}")
            break


def analyze(text, context=None):
    context = text if context is None else context
    ctx = URL_RE.sub(" ", UPI_RE.sub(" ", context)).lower()
    found = {}

    def add(sid, strength, evidence):
        if sid not in found or strength > found[sid][0]:
            found[sid] = (strength, evidence)

    for uri in UPI_RE.findall(text):
        check_upi(uri, ctx, add)

    results = []
    for url in URL_RE.findall(text):
        results.append(check_url(url.rstrip(".,;:!?)\"'"), ctx, add))

    # Dampener only when every link in the case is clean and official.
    if results and all(r is not None for r in results):
        all_https = all(r[1] for r in results)
        add("official_domain_match", 1.0 if all_https else 0.6, results[0][0])

    return [make(sid, s, e) for sid, (s, e) in found.items()]