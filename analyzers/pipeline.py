"""Runs every analyzer on one case and merges their signals.

An analyzer that fails never breaks the whole check: its signals are simply
skipped and the failure is reported in the returned notes.
"""
import logging

from analyzers.link_qr import analyze as analyze_links
from analyzers.message import analyze as analyze_message

log = logging.getLogger("sentra")


def scan_with_notes(text, context=None):
    merged, notes = {}, []
    for name, fn in (("message", lambda: analyze_message(text)),
                     ("link and QR", lambda: analyze_links(text, context))):
        try:
            sigs = fn()
        except Exception as e:  # never let one analyzer take the app down
            log.error("%s analyzer failed: %s", name, type(e).__name__)
            notes.append(f"The {name} reader could not process part of that input.")
            continue
        for s in sigs:
            if s["id"] not in merged or s["strength"] > merged[s["id"]]["strength"]:
                merged[s["id"]] = s
    return sorted(merged.values(), key=lambda s: s["id"]), notes


def scan(text, context=None):
    return scan_with_notes(text, context)[0]
