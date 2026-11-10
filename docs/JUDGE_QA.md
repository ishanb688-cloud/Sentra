# Judge Q&A: honest answers

Short, truthful answers to the questions a technical judge is most likely to ask. Every number comes from
`docs/BENCHMARK.md` and `docs/HOLDOUT.md`, and every claim can be checked in the code.

---

## 1. Where exactly is the AI? Is it genuinely AI-powered or rule-based?

**It is rule-based.** Sentra is an explainable expert system: automated reasoning over four kinds of evidence, not a
trained machine-learning model, and we do not claim otherwise.

What is "intelligent" about it: it reads messages, links, UPI/QR payloads and app files **together**, scores each warning
sign with a weighted evidence model, and recognises **multi-step scam scripts across items** (for example a bank
impersonation message, plus a lookalike link, plus a request for an OTP).

Why rules, on purpose:
- Every verdict can be traced to named signals, so a person can see *why* something is risky. A black-box score cannot do that.
- There is no large, consented, labelled dataset of Indian scam messages we could legitimately train on.
- The output is deterministic, and no message is ever sent anywhere to train a model.

The cost is real: it does not learn new scams by itself. **Roadmap:** add a text classifier trained on consented, labelled
data as one more *signal source*, keeping the rule engine as the explanation and safety layer.

## 2. How do you calculate the risk score?

Each warning sign has a **strength** (how clearly it appears) and a **reliability** (how trustworthy that kind of sign is).
Weight = strength x reliability. Signs in a category combine with diminishing returns (`1 - product(1 - w)`);
categories combine at 0.6 scale so no single kind of sign reaches the top; a completed **scam script** adds a bonus; an
official-domain match lowers the score but is **capped** so it cannot hide a full script. Levels: under 0.30 Low signals,
under 0.65 Suspicious, under 0.85 High risk, otherwise Critical. The same input always gives the same score (tested).
Full formulas and a computed example are in `docs/METHODOLOGY.md`.

**Honest caveat:** the weights are expert judgement checked against our test sets, not statistically fitted. With real
labelled data we would calibrate them.

## 3. How do you verify APK permissions and publisher signatures?

Static analysis only; the app is never installed or run. We read the manifest and package with the Androguard library:
permissions (SMS read plus screen overlay), SMS-interception priority, accessibility and device-admin requests, hidden
app or code files inside the package, the installer permission, whether it carries a valid signature, whether it is signed
with a **developer debug certificate** (real published apps never are), a hidden launcher icon, and whether a bank-like
name uses that bank's **official package ID** (kept in `data/brands.json`).

**What we do not do yet:** compare the publisher certificate against each brand's official certificate fingerprint. That
needs a trusted reference list, and we will not invent one. We tested the reader on a real open-source Android app
(clean result) and on synthetic permission profiles; we have **not** tested on real malware.

## 4. How do you distinguish a legitimate UPI payment from a fraudulent one?

We cannot know the account holder's **registered name**, because only your UPI app can see that. What we check: whether the
code **sends** money while the message says you will **receive** it; a payee named like a refund, cashback or prize
(refunds come *to* you); a payee name that does not match the brand the message claims to be; a business-sounding name on a
personal phone-number ID; and an unfamiliar UPI handle. The result card shows who the code says it will pay and tells the
user to compare it with the name their UPI app shows. We never call a payment safe.

## 5. What happens when a completely new scam appears?

It may slip through, and we say so on the website. Partial protection comes from the fact that most scams share general
tells (impersonation, pressure, requests for codes or money, lookalike links), which the signals capture without needing
the exact wording. On our **unseen holdout set** (never used to adjust the rules) Sentra flagged 17 of 22 scams, so roughly
one in four was missed. Updating is cheap: signals and scam scripts are data files, not code. The longer-term answer is a
learned component plus a reporting loop.

---

## More questions you may get

**How do you know it works?** `python tools/benchmark.py`. 90 labelled cases: the **first run before any tuning** flagged
94.8% of scams with 2 false alarms in 32 genuine items; after fixing the general weaknesses it showed, 100% and 0. A fresh
40-case **holdout** set, never tuned on: **77.3% flagged, 94.4% precision, 1 false alarm in 18 genuine (5.6%)**. The cases
were written by our team, so this is **not independent real-world validation**. We say that on the site.

**What are the false positives?** A delivery or ride OTP that is *meant* to be shared in person is flagged (one of the
holdout cases). Mitigation today: the evidence is shown so the user can judge. Next step: recognise "share with the
delivery agent at your door" context.

**Which scams does it miss?** Investment and crypto scams with no warning words; lookalike domains that only add a prefix to
a brand (for example `paytmbank-kyc.in`); vishing that gives a mobile number without other pressure.

**Why not follow redirects and open links?** Opening an unknown link from a server can expose us and the user, and it breaks
the promise that Sentra never visits what you give it. A shortened link is flagged because it *hides* the destination. We
removed the unsupported "redirect chain" signal rather than claim it.

**Is user data stored?** No. Messages are processed in memory. Uploaded files are deleted right after reading. History keeps
only the result, the kind and the time, in the user's own browser. See `docs/SECURITY.md`.

**Can an attacker evade it?** Any public rule set can be probed. Scam scripts, capped dampeners and combining several kinds
of evidence make casual evasion harder, but this is guidance, not a guarantee, and the site says so.

**What is original?** Not a single check, but the combination: four kinds of input in one case; scam-script reasoning across
them; a replay showing how the scam would have played out; and a QR check that shows what the code *does*. We searched for
similar tools and describe this as a combination, not as a first.

**How would it scale?** The server is stateless. The only shared state to add is the rate limiter (a shared store).
