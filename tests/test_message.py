from analyzers.message import analyze


def ids(text):
    return {s["id"] for s in analyze(text)}


def test_otp_request_is_detected():
    assert "msg_otp_request" in ids("Please share the OTP you receive to verify")


def test_bank_warning_sentence_is_ignored():
    assert "msg_otp_request" not in ids("Do not share OTP with anyone. -SBI")


def test_friend_message_is_clean():
    assert ids("Hey are you coming for dinner tonight? Call me when you reach.") == set()


def test_toll_free_dispute_line_is_not_pressure_but_a_mobile_number_is():
    genuine = "Rs 500 debited from A/c XX1234. If not you, call 1800-1234 immediately. -HDFC Bank"
    scam = "Rs 500 debited from A/c XX1234. If not you, call 9876543210 immediately. -HDFC Bank"
    assert "msg_deadline_pressure" not in ids(genuine)
    assert "msg_deadline_pressure" in ids(scam)


def test_dear_customer_alone_is_a_weak_hint():
    sig = [s for s in analyze("Dear customer, your statement is ready.") if s["id"] == "msg_authority_claim"]
    assert sig and sig[0]["strength"] <= 0.5


def test_wrong_transfer_scam_is_recognised():
    assert "msg_wrong_transfer" in ids("I sent Rs 10,000 to your number by mistake. Please return the amount now.")


def test_disconnection_threat_is_recognised():
    assert "msg_threat_block" in ids("Your connection will be cut tonight")


def test_delivery_otp_shared_with_agent_at_doorstep_is_not_treated_as_bank_otp_theft():
    text = "Your Flipkart order is out for delivery. Share the delivery OTP 4821 with the agent only at your doorstep."
    assert "msg_otp_request" not in ids(text)


def test_amazon_pay_cashback_credit_is_not_a_payment_demand_or_authority_claim():
    text = "Your Amazon Pay balance was credited with Rs 100 cashback for your recent purchase."
    found = ids(text)
    assert "msg_payment_demand" not in found
    assert "msg_authority_claim" not in found


def test_school_fee_notice_does_not_get_a_strong_upfront_payment_signal():
    text = "Dear parent, school fee of Rs 15,000 is due by 30 Nov. Pay on the school portal. A late fee of Rs 500 applies after the due date."
    payment = [s for s in analyze(text) if s["id"] == "msg_payment_demand"]
    assert not payment or payment[0]["strength"] <= 0.7
