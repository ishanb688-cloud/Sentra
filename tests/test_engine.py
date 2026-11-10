from engine.fusion import fuse, make

KYC = lambda: [make("msg_authority_claim", 1.0), make("msg_threat_block", 1.0), make("msg_otp_request", 1.0)]


def test_genuine_alert_stays_low():
    assert fuse([make("known_sender_format", 1.0), make("msg_authority_claim", 0.6)])["level"] == "Low signals"


def test_complete_kyc_chain_is_critical():
    r = fuse(KYC())
    assert (r["level"], r["chain"]) == ("Critical", "fake_kyc")


def test_lone_weak_hint_is_low():
    assert fuse([make("link_shortener", 0.6)])["level"] == "Low signals"


def test_official_link_cannot_hide_a_full_chain():
    r = fuse(KYC() + [make("official_domain_match", 1.0)])
    assert r["chain"] == "fake_kyc" and r["level"] in ("High risk", "Critical")


def test_threat_without_a_request_is_only_suspicious():
    assert fuse([make("msg_authority_claim", 1.0), make("msg_threat_block", 1.0)])["level"] == "Suspicious"


def test_chain_comes_with_replay_steps():
    assert len(fuse(KYC())["replay"]) >= 3


def test_chain_that_needs_a_specific_signal_only_fires_with_it():
    base = [make("msg_payment_demand", 1.0), make("msg_deadline_pressure", 1.0)]
    assert fuse(base)["chain"] != "wrong_transfer"
    assert fuse(base + [make("msg_wrong_transfer", 1.0)])["chain"] == "wrong_transfer"


def test_same_signals_give_the_same_score_in_any_order():
    sigs = KYC() + [make("link_shortener", 1.0), make("link_suspicious_tld", 1.0)]
    results = {(fuse(sigs)["risk"], fuse(list(reversed(sigs)))["risk"]) for _ in range(25)}
    assert len({a for a, _ in results} | {b for _, b in results}) == 1


def test_no_signals_means_zero_risk():
    r = fuse([])
    assert r["risk"] == 0 and r["level"] == "Low signals" and r["chain"] is None
