# Signal catalog

Generated from `data/signals.json`. Refresh with `python tools/make_signal_docs.py`.

| Signal | Category | Reliability | Meaning |
|---|---|---|---|
| `msg_otp_request` | credential_theft | 0.90 | Asks you to share a one-time password, which no real bank does. |
| `msg_install_request` | device_takeover | 0.80 | Tells you to install an app or file from a message. |
| `msg_secrecy_isolation` | obfuscation | 0.75 | Pushes you to stay secret or stay on the line. |
| `msg_kyc_update` | credential_theft | 0.70 | Demands an urgent KYC or account detail update. |
| `msg_payment_demand` | financial_redirect | 0.65 | Asks for a fee, deposit, or transfer. |
| `msg_threat_block` | urgency | 0.65 | Threatens blocking, legal action, or arrest. |
| `msg_authority_claim` | impersonation | 0.60 | Claims to be a bank, police, courier, or government body. |
| `msg_reward_lure` | financial_redirect | 0.60 | Dangles a refund, prize, or cashback. |
| `msg_deadline_pressure` | urgency | 0.55 | Creates a tight deadline to stop you thinking. |
| `msg_unknown_shortlink` | obfuscation | 0.50 | Shortened link from an unknown sender. |
| `qr_payee_mismatch` | financial_redirect | 0.90 | The payee name does not match the merchant mentioned. |
| `link_lookalike_brand` | impersonation | 0.85 | The domain is a near-copy of a known brand. |
| `link_punycode` | impersonation | 0.85 | Look-alike characters are used in the domain. |
| `qr_pay_not_receive` | financial_redirect | 0.85 | The QR sends money, but you were told you would receive it. |
| `link_brand_in_subdomain` | impersonation | 0.80 | A brand name is placed in front of an unrelated domain. |
| `link_credential_form` | credential_theft | 0.80 | A login or OTP form sits on a non-official domain. |
| `link_odd_host` | obfuscation | 0.70 | The link points to a raw IP address or odd host. |
| `link_redirect_chain` | obfuscation | 0.60 | The link bounces through several hops. |
| `link_suspicious_tld` | obfuscation | 0.50 | The domain ending is often abused by scammers. |
| `link_shortener` | obfuscation | 0.45 | A shortener hides the real destination. |
| `link_apk_download` | device_takeover | 0.80 | The link downloads an app file directly instead of opening a page. |
| `app_sms_plus_overlay` | device_takeover | 0.90 | Can read your SMS and draw over other apps, enough to steal OTPs. |
| `app_name_mimics_bank` | impersonation | 0.80 | Name or icon imitates a bank or government service. |
| `app_accessibility_service` | device_takeover | 0.75 | Asks for accessibility control of your screen. |
| `app_hides_icon` | obfuscation | 0.75 | Tries to hide itself from your app list. |
| `app_package_mismatch` | impersonation | 0.70 | Its package identity does not match its claimed purpose. |
| `app_device_admin` | device_takeover | 0.70 | Requests device-administrator rights. |
| `app_call_forwarding` | credential_theft | 0.70 | Can redirect your calls. |
| `app_sms_read` | device_takeover | 0.40 | Can read your text messages. |
| `app_excess_permissions` | device_takeover | 0.50 | Asks for far more permissions than its purpose needs. |
| `app_unverified_signer` | obfuscation | 0.40 | No recognized publisher signature. |
| `official_domain_match` | dampener | 0.30 | The link is on a verified official domain. |
| `no_action_requested` | dampener | 0.25 | The message asks you to do nothing. |
| `known_sender_format` | dampener | 0.25 | Matches a genuine alert format with masked digits and no link. |
