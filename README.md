# Phishing Email Detector (Rule-Based)

A beginner-friendly Python tool that scans an email's subject, sender, and
body text, then scores it for common phishing red flags.

## How It Works

This is a **rule-based** detector — it doesn't use AI/Machine Learning.
Instead, it checks for known warning signs real phishing emails use, and
adds up a "risk score":

| Check | What it looks for |
|---|---|
| Urgency language | "verify your account," "act now," "suspended," etc. |
| Money/prize bait | "you have won," "claim your reward," "lottery" |
| Brand impersonation | Email mentions a brand (e.g. PayPal) but links don't go to that brand's real website |
| Suspicious links | Links using odd domain endings (.xyz, .top), raw IP addresses, or overly complex domains |
| Sender spoofing | "Official" sender using a free email address, or numbers swapped into letters (e.g. `paypa1`, `amaz0n`) |
| Generic greeting | "Dear Customer" instead of your real name |

**Score guide:**
- 0–2 → 🟢 Likely Safe
- 3–5 → 🟠 Suspicious
- 6+ → 🔴 Likely Phishing

## How to Run It

```bash
python3 phishing_detector.py
```

This runs 4 built-in examples (2 phishing, 1 scam, 1 safe email) so you can
see the detector in action immediately.

## Testing Your Own Email

Open `phishing_detector.py`, scroll to the bottom section marked
`# ---- Try your own email here ----`, and replace `my_subject`,
`my_sender`, and `my_text` with any email you want to check. Then run the
script again.

## Limitations (Good to Know)

- This is a **rule-based** tool, not Machine Learning — it can be fooled by
  a well-written phishing email that avoids these specific patterns.
- It's a learning/demo project, not a production-grade security tool.
- A more advanced version could add: SPF/DKIM header checking, a trained ML
  classifier on a labeled phishing dataset, or real-time link reputation
  checking via an API.

## Author
Muhammad Maaz Afridi
