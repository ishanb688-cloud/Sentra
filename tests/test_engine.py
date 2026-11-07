from engine.fusion import fuse, make

KYC = lambda: [make("msg_authority_claim", 1.0),
               make("msg_threat_block", 1.0),
               make("msg_otp_request", 1.0)]


def test_genuine_alert_stays_low():
    sigs = [make("known_sender_format", 1.0), make("msg_authority_claim", 0.6)]
    assert fuse(sigs)["level"] == "Low signals"


def test_complete_kyc_chain_is_critical():
    r = fuse(KYC())
    assert r["level"] == "Critical"
    assert r["chain"] == "fake_kyc"


def test_lone_weak_hint_is_low():
    assert fuse([make("link_shortener", 0.6)])["level"] == "Low signals"


def test_official_link_cannot_hide_a_full_chain():
    r = fuse(KYC() + [make("official_domain_match", 1.0)])
    assert r["chain"] == "fake_kyc"
    assert r["level"] in ("High risk", "Critical")


def test_threat_without_a_request_is_only_suspicious():
    sigs = [make("msg_authority_claim", 1.0), make("msg_threat_block", 1.0)]
    assert fuse(sigs)["level"] == "Suspicious"


def test_chain_comes_with_replay_steps():
    assert len(fuse(KYC())["replay"]) >= 3