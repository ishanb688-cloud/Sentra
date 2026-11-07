from analyzers.message import analyze


def ids(text):
    return {s["id"] for s in analyze(text)}


def test_otp_request_is_detected():
    assert "msg_otp_request" in ids("Please share the OTP you receive to verify")


def test_bank_warning_sentence_is_ignored():
    assert "msg_otp_request" not in ids("Do not share OTP with anyone. -SBI")


def test_friend_message_is_clean():
    assert ids("Hey are you coming for dinner tonight? Call me when you reach.") == set()