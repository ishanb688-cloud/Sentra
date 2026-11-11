"""Regression tests for the message-scanning misses found during product testing."""
from analyzers.message import analyze
from engine.fusion import fuse, make


def signal_ids(text):
    return {signal["id"] for signal in analyze(text)}


def test_recruitment_registration_fee_is_detected():
    text = (
        "Congratulations! Your resume has been shortlisted for Amazon Work From Home. "
        "Earn ₹35,000 per month. Pay a refundable registration fee of ₹499 to confirm your job."
    )
    ids = signal_ids(text)
    assert "msg_job_fee" in ids
    assert "msg_payment_demand" in ids
    assert "msg_job_lure" in ids


def test_recruitment_security_deposit_is_detected():
    text = (
        "Dear Candidate, your Amazon interview is scheduled for tomorrow. "
        "Please complete your application by paying the mandatory security deposit of ₹799."
    )
    ids = signal_ids(text)
    assert "msg_job_fee" in ids
    assert "msg_payment_demand" in ids


def test_normal_job_interview_message_is_not_a_fee_scam_signal():
    text = (
        "Thank you for applying for the Software Engineering Intern position. "
        "Our recruitment team will contact shortlisted candidates through the official careers portal."
    )
    ids = signal_ids(text)
    assert "msg_job_fee" not in ids
    assert "msg_job_lure" not in ids


def test_failed_amazon_order_delivery_is_recognised_as_impersonation_context():
    text = (
        "Your Amazon order #IN458921 could not be delivered. "
        "Click here to reschedule your delivery and verify your details."
    )
    assert "msg_authority_claim" in signal_ids(text)


def test_delivery_fee_message_detects_payment_and_deadline():
    text = (
        "Dear Customer, your package is on hold due to an incomplete address. "
        "Pay ₹25 redelivery charges and confirm your address within 6 hours."
    )
    ids = signal_ids(text)
    assert "msg_authority_claim" in ids
    assert "msg_payment_demand" in ids
    assert "msg_deadline_pressure" in ids


def test_qr_replay_requires_actual_qr_pay_not_receive_evidence():
    signals = [
        make("msg_payment_demand", 1.0, "Pay ₹25 redelivery charges"),
        make("msg_deadline_pressure", 1.0, "within 6 hours"),
    ]
    assert fuse(signals)["chain"] != "qr_reverse"


def test_qr_replay_appears_when_qr_pay_not_receive_signal_exists():
    signals = [
        make("qr_pay_not_receive", 1.0, "QR sends money instead of receiving"),
        make("msg_deadline_pressure", 1.0, "within 6 hours"),
    ]
    assert fuse(signals)["chain"] == "qr_reverse"



def test_investment_profit_promise_without_guaranteed_keyword_is_detected():
    text = "Join our forex investment plan. Earn 30% profit per day with our trading account."
    assert "msg_investment_lure" in signal_ids(text)


def test_job_registration_fee_with_employee_id_language_is_detected():
    text = "Your work from home position is confirmed. Pay Rs 299 for employee ID generation and onboarding."
    ids = signal_ids(text)
    assert "msg_job_fee" in ids


def test_delivery_registration_fee_scam_is_detected():
    text = "Your courier parcel is held. Pay delivery fee of Rs 49 immediately using this link to release it."
    ids = signal_ids(text)
    assert "msg_delivery_fee_scam" in ids
    assert "msg_payment_demand" in ids


def test_genuine_delivery_otp_at_doorstep_is_not_credential_theft():
    text = "Your Flipkart order is out for delivery. Share the delivery OTP 4821 with the agent only at your doorstep."
    ids = signal_ids(text)
    assert "msg_otp_request" not in ids
    assert "msg_delivery_fee_scam" not in ids


def test_competition_prize_message_with_reply_action_is_flagged():
    text = "Free entry in our weekly competition to win a £900 prize. Text WIN to 80086 now."
    assert "msg_competition_lure" in signal_ids(text)


def test_selected_prize_with_callback_request_is_flagged():
    text = "You have been selected to receive a £900 prize reward. To claim call 09061701461."
    ids = signal_ids(text)
    assert "msg_reward_lure" in ids
    assert "msg_premium_rate_contact" in ids


def test_premium_rate_number_without_contact_instruction_is_not_flagged():
    assert "msg_premium_rate_contact" not in signal_ids("Reference code 09061701461 is printed on your old receipt.")


def test_ordinary_competition_notice_without_prize_or_action_is_not_flagged():
    text = "The annual college competition timetable is available on the student portal."
    assert "msg_competition_lure" not in signal_ids(text)


def test_genuine_free_trial_message_is_not_flagged_as_competition_scam():
    text = "Your free trial starts today. You can cancel anytime in account settings."
    ids = signal_ids(text)
    assert "msg_competition_lure" not in ids
    assert "msg_premium_rate_contact" not in ids
