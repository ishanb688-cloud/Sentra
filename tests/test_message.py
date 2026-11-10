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


def test_guaranteed_crypto_returns_are_flagged_as_investment_lure():
    text = "Invest Rs 5,000 in our crypto plan and get Rs 20,000 in 2 days. Guaranteed returns."
    assert "msg_investment_lure" in ids(text)


def test_card_charge_alert_with_mobile_helpline_is_suspicious():
    text = "Your credit card has been charged Rs 49,999 for iPhone. If not authorised, call our helpline 7011223344 immediately."
    assert "msg_card_charge_impersonation" in ids(text)


def test_genuine_bank_dispute_toll_free_number_is_not_flagged_as_mobile_helpline():
    text = "Alert: Rs 15,000 debited from your A/c XX7712 at ATM on 08-11. Not you? Call 1800-425-1111 now. -Axis Bank"
    assert "msg_card_charge_impersonation" not in ids(text)


def test_parcel_address_is_incorrect_is_impersonation_context():
    assert "msg_authority_claim" in ids("Hello sir, your parcel address is incorrect. Update here to avoid return.")


def test_online_task_recharge_scam_is_detected_and_explained():
    from engine.fusion import fuse
    text = (
        "Earn Rs 3,000 daily by liking videos in our Telegram task group. "
        "Recharge Rs 1,000 to unlock VIP prepaid tasks and withdraw your earnings."
    )
    signals = analyze(text)
    assert "msg_task_scam" in {s["id"] for s in signals}
    result = fuse(signals)
    assert result["chain"] == "task_recharge"
    assert result["level"] in ("Suspicious", "High risk", "Critical")


def test_legitimate_task_list_without_payment_request_is_not_task_scam():
    text = (
        "Complete the online training tasks by Friday: watch the lesson, "
        "review the worksheet, and submit your answers. No payment is required."
    )
    assert "msg_task_scam" not in {s["id"] for s in analyze(text)}


# Hindi and Hinglish coverage: common scam wording used in Indian SMS/WhatsApp.
def test_hinglish_otp_request_is_detected():
    assert "msg_otp_request" in ids("Apna OTP mujhe WhatsApp par bhejo, account verify karna hai.")


def test_hindi_bank_warning_not_misclassified_as_otp_theft():
    assert "msg_otp_request" not in ids("Apna OTP kisi ke saath share na karein. Bank kabhi OTP nahi maangta.")


def test_hinglish_kyc_update_and_account_threat_are_detected():
    found = ids("Aapka KYC expire ho gaya hai. Aaj hi Aadhaar update karo warna account band ho jayega.")
    assert "msg_kyc_update" in found
    assert "msg_threat_block" in found


def test_hinglish_payment_demand_is_detected():
    assert "msg_payment_demand" in ids("₹499 registration fee abhi jama karo aur job confirm karo.")


def test_hinglish_task_recharge_scam_is_detected():
    text = "Telegram par video like karke paise kamao. Withdrawal kholne ke liye ₹1,000 recharge karo."
    assert "msg_task_scam" in ids(text)
