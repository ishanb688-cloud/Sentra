"""Finds links in free text, including bare domains such as example.com
and addresses without a scheme. Never visits anything."""
import re

TLDS = ("com|in|co\\.in|net|org|info|biz|xyz|top|click|work|buzz|icu|rest|cfd|sbs|cyou|"
        "online|site|shop|live|link|app|store|tech|pro|vip|club|me|io|co|cc|ws|tk|ml|ga|cf|gq|"
        "one|page|today|fun|space|website|cloud|gov\\.in|nic\\.in|org\\.in|net\\.in|ac\\.in|edu\\.in|apk")

SCHEME = re.compile(r"(?:https?|ftp)://[^\s<>\"']+", re.I)
DOMAIN = re.compile(
    r"(?<![@\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + TLDS + r"))(?![a-z0-9-])"
    r"(?::\d{2,5})?(?:[/?#][^\s<>\"']*)?", re.I)
SHORTLINK = re.compile(r"(?<![\w./-])(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|goo\.gl|shorturl\.at|tiny\.cc|ow\.ly)(?:/[^\s<>\"']*)?", re.I)
UPI = re.compile(r"upi://pay\?[^\s<>\"']+", re.I)
TRAILING = ".,;:!?)]}'\""


def _clean(u):
    return u.rstrip(TRAILING)


def find_urls(text):
    """Return links found in text, in order, without duplicates."""
    text = UPI.sub(" ", text or "")
    found, spans = [], []
    for rx in (SCHEME, SHORTLINK):
        for m in rx.finditer(text):
            found.append((m.start(), _clean(m.group(0))))
            spans.append((m.start(), m.end()))
    masked = list(text)
    for a, b in spans:
        for i in range(a, b):
            masked[i] = " "
    for m in DOMAIN.finditer("".join(masked)):
        found.append((m.start(), _clean(m.group(0))))
    out, seen = [], set()
    for _, u in sorted(found):
        if u and u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


def strip_urls(text):
    """Text with links and UPI addresses removed, for wording analysis."""
    text = UPI.sub(" ", text or "")
    text = SCHEME.sub(" ", text)
    text = SHORTLINK.sub(" ", text)
    return DOMAIN.sub(" ", text)
