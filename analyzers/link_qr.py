"""Reads link addresses and UPI payment payloads. Static analysis only:
Sentra never visits a link, so there is no redirect following."""
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzers.urls import UPI, find_urls, strip_urls
from engine.fusion import make

DATA = Path(__file__).resolve().parent.parent / "data"
with open(DATA / "brands.json", encoding="utf-8") as f:
    BRANDS = json.load(f)

OFFICIAL = {d for b in BRANDS for d in b["domains"]}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co",
              "goo.gl", "shorturl.at", "tiny.cc", "ow.ly"}
BAD_TLDS = {"xyz", "top", "click", "work", "buzz", "icu", "rest", "gq", "tk",
            "ml", "cf", "ga", "monster", "cfd", "sbs", "cyou", "vip", "fun"}
TWO_LEVEL = {"co.in", "gov.in", "nic.in", "org.in", "net.in", "ac.in", "edu.in",
             "res.in", "co.uk", "com.au"}
HANDLES = {"ybl", "ibl", "axl", "okhdfcbank", "okicici", "okaxis", "oksbi", "paytm", "apl",
           "upi", "sbi", "hdfcbank", "icici", "axisbank", "pnb", "boi", "cnrb", "unionbank",
           "idfcfirst", "fbl", "kotak", "airtel", "jio", "postbank", "yesbank", "freecharge",
           "waicici", "wasbi", "waaxis", "wahdfcbank", "okbizaxis", "okbizicici", "indus",
           "rbl", "federal", "dbs", "aubank", "ikwik", "ptyes", "pthdfc", "ptaxis", "ptsbi"}

# Large platforms whose domains merely contain a brand name; no lookalike signal, no trust bonus.
NEUTRAL = {"amazonaws.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "withgoogle.com"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "$": "s", "@": "a"})
CRED_PATH = re.compile(r"(login|log-in|signin|sign-in|verify|verification|kyc|otp|password|passcode|secure|auth|update|account|claim|redeem|unlock)", re.I)
RECEIVE = re.compile(r"\b(receive|received|credited|refund|cashback|prize|reward|you have won|claim|collect)\b", re.I)
# Names that promise money TO you. A code that pays someone with such a name is contradictory.
RECEIVE_NAME = re.compile(r"\b(refund|cashback|reward|prize|lucky|winner|claim|bonus)s?\b", re.I)
BUSINESS = re.compile(r"(store|shop|mart|traders|enterprise|pvt|ltd|official|support|refund|bank|care|helpdesk|rewards?)", re.I)


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


def brand_hits(tokens, joined=""):
    hits = {}
    for b in BRANDS:
        for bt in b["tokens"]:
            for t in tokens:
                if t == bt or (len(bt) >= 6 and joined and bt in joined and t == joined):
                    kind = "embedded"
                elif norm(t) == bt:
                    kind = "homoglyph"
                elif (len(bt) >= 5 and t.startswith(bt) and len(t) > len(bt)
                      and re.search(r"(bank|kyc|login|secure|verify|support|refund|account|update)", t[len(bt):])):
                    kind = "brand_prefix"
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
    """Adds signals for one link. Returns (domain, https) if it is clean and official."""
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*):", url, re.I)
    if scheme_match and scheme_match.group(1).lower() not in ("http", "https"):
        add("link_odd_host", 1.0, f"unsafe or unsupported URL scheme {scheme_match.group(1).lower()}")
        return None
    raw = url if re.match(r"^https?://", url, re.I) else "http://" + url
    try:
        p = urlparse(raw)
        host = unquote(p.hostname or "").lower()
        port = p.port
    except ValueError:
        add("link_odd_host", 0.6, "malformed address")
        return None
    if not host:
        return None

    https = raw.lower().startswith("https://")
    path_q = unquote((p.path or "") + "?" + (p.query or ""))
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
    if (p.path or "").lower().endswith(".apk") or host.endswith(".apk"):
        add("link_apk_download", 1.0, "direct app-file download")

    brand_hit = False
    if not official and not is_ip and reg not in SHORTENERS and reg not in NEUTRAL:
        label = reg.split(".")[0]
        joined = label.replace("-", "").replace("_", "")
        tokens = list({*re.split(r"[-_]", label), joined})
        for name, (kind, tok, prio, b) in brand_hits(tokens, joined).items():
            said = mentions(b, ctx)
            if kind == "embedded":
                add("link_lookalike_brand", 1.0 if said else 0.8,
                    f"{name} name inside unofficial domain {reg}")
            else:
                add("link_lookalike_brand", 1.0 if said else 0.9, f"'{tok}' imitates {name} on {reg}")
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
    try:
        q = parse_qs(urlparse(uri).query)
    except ValueError:
        return
    pa = (q.get("pa", [""])[0] or "").strip()
    pn = unquote(q.get("pn", [""])[0] or "").strip()
    payee = re.sub(r"[^a-z0-9]", "", (pn + pa).lower())

    if RECEIVE.search(ctx):
        add("qr_pay_not_receive", 1.0, "payment request, but the message talks about receiving money")
    if RECEIVE_NAME.search(pn):
        add("qr_pay_not_receive", 0.9, f"the payee is named '{pn}', but this code sends money instead of receiving it")
    for b in BRANDS:
        if mentions(b, ctx) and not any(t in payee for t in b["tokens"]):
            add("qr_payee_mismatch", 1.0, f"message mentions {b['name']} but the payee is {pn or pa}")
            break
    user, _, handle = pa.partition("@")
    pnl = pn.lower()
    business = BUSINESS.search(pnl) or any(t in pnl for b in BRANDS for t in b["tokens"])
    if pa and user.isdigit() and len(user) >= 10 and business:
        add("qr_name_handle_mismatch", 0.8, f"'{pn}' is paid through a personal number ({pa})")
    if pa and (not handle or handle.lower() not in HANDLES):
        add("qr_unknown_handle", 1.0, f"UPI ID {pa} has an unfamiliar format or handle")


def analyze(text, context=None):
    text = text or ""
    context = text if context is None else context
    ctx = strip_urls(context).lower()
    found = {}

    def add(sid, strength, evidence):
        if sid not in found or strength > found[sid][0]:
            found[sid] = (strength, evidence)

    for uri in UPI.findall(text):
        check_upi(uri, ctx, add)

    results = [check_url(u, ctx, add) for u in find_urls(text)]
    if results and all(r is not None for r in results):
        add("official_domain_match", 1.0 if all(r[1] for r in results) else 0.6, results[0][0])
    return [make(sid, s, e) for sid, (s, e) in found.items()]
