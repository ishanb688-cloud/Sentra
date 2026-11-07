from analyzers.message import analyze as analyze_message
from analyzers.link_qr import analyze as analyze_links


def scan(text, context=None):
    merged = {}
    for s in analyze_message(text) + analyze_links(text, context):
        if s["id"] not in merged or s["strength"] > merged[s["id"]]["strength"]:
            merged[s["id"]] = s
    return list(merged.values())