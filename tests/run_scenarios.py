import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.fusion import fuse, make

scenarios = {
    "genuine bank alert": [
        make("known_sender_format", 1.0),
        make("msg_authority_claim", 0.6),
    ],
    "fake KYC message": [
        make("msg_authority_claim", 1.0),
        make("msg_threat_block", 1.0),
        make("msg_otp_request", 1.0),
    ],
    "lone weak hint": [
        make("link_shortener", 0.6),
    ],
    "chain + official link": [
        make("msg_authority_claim", 1.0),
        make("msg_threat_block", 1.0),
        make("msg_otp_request", 1.0),
        make("official_domain_match", 1.0),
    ],
        "bank threat, no ask": [
        make("msg_authority_claim", 1.0),
        make("msg_threat_block", 1.0),
    ],
    "courier fee, no link": [
        make("msg_authority_claim", 1.0),
        make("msg_payment_demand", 1.0),
    ],
}

for name, sigs in scenarios.items():
    r = fuse(sigs)
    print(f"{name:25} risk={r['risk']:<6} level={r['level']:<14} chain={r['chain']}")
