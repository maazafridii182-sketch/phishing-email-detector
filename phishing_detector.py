"""
Phishing Email Detector (Rule-Based)
-------------------------------------
A beginner-friendly cybersecurity tool that analyzes an email's text and
sender address, then scores it for common phishing red flags.

How it works:
Each suspicious pattern found adds points to a "risk score."
At the end, the total score decides the verdict:
    0-2   -> Likely Safe
    3-5   -> Suspicious
    6+    -> Likely Phishing

This is a RULE-BASED detector (not AI/ML) — it checks for known red flags
that real phishing emails commonly use.
"""

import re


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "act now", "suspended",
    "click here", "limited time", "expires today", "confirm your identity",
    "unusual activity", "final notice", "your account will be closed",
    "update your information", "restricted", "unauthorized login",
]

MONEY_WORDS = [
    "won a prize", "you have won", "claim your reward", "free gift",
    "lottery", "tax refund", "bank transfer", "wire transfer",
]

# Well-known brands that phishing emails frequently impersonate.
# Used to check for look-alike / mismatched domains.
COMMON_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "bank": None,  # generic — handled separately
}

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".info", ".loan", ".gq", ".tk"]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def find_urls(text):
    """Extract URLs from the email body."""
    return re.findall(r"https?://[^\s\)\]\"']+", text)


def domain_of(url):
    """Pull just the domain out of a URL."""
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1).lower() if match else ""


def check_urgency_language(text, findings, score):
    text_lower = text.lower()
    hits = [w for w in URGENCY_WORDS if w in text_lower]
    if hits:
        score += min(len(hits), 3) * 1  # cap contribution at 3 points
        findings.append(f"Urgency/pressure language found: {', '.join(hits[:4])}")
    return score


def check_money_bait(text, findings, score):
    text_lower = text.lower()
    hits = [w for w in MONEY_WORDS if w in text_lower]
    if hits:
        score += 2
        findings.append(f"Prize/money bait language found: {', '.join(hits)}")
    return score


def check_brand_impersonation(text, findings, score):
    """If a brand name is mentioned but the links don't point to that brand's
    real domain, that's a classic phishing sign (a fake PayPal email whose
    links go to some random site)."""
    text_lower = text.lower()
    urls = find_urls(text)
    domains = [domain_of(u) for u in urls]

    for brand, real_domain in COMMON_BRANDS.items():
        if brand in text_lower and real_domain:
            mismatched = [d for d in domains if real_domain not in d]
            if domains and len(mismatched) == len(domains):
                score += 3
                findings.append(
                    f"Email mentions '{brand}' but none of its links go to {real_domain} "
                    f"(found: {', '.join(domains) if domains else 'no links'})"
                )
    return score


def check_suspicious_links(text, findings, score):
    urls = find_urls(text)
    if not urls:
        return score

    for url in urls:
        domain = domain_of(url)
        # Suspicious top-level domains
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 2
            findings.append(f"Link uses a commonly-abused domain ending: {url}")
        # Raw IP address instead of a domain name
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            score += 3
            findings.append(f"Link uses a raw IP address instead of a domain: {url}")
        # Excessive subdomains / hyphens often used to mimic real brands
        if domain.count("-") >= 2 or domain.count(".") >= 4:
            score += 1
            findings.append(f"Link domain looks unusually complex/mimicking: {url}")

    return score


def check_sender_address(sender, findings, score):
    if not sender:
        return score
    sender_lower = sender.lower()

    # Free email domains claiming to be an official company
    free_domains = ["@gmail.com", "@yahoo.com", "@outlook.com", "@hotmail.com"]
    for brand in COMMON_BRANDS:
        if brand in sender_lower.split("@")[0] and any(fd in sender_lower for fd in free_domains):
            score += 3
            findings.append(
                f"Sender claims to be '{brand}' but uses a free email domain ({sender}) "
                f"instead of an official company domain"
            )

    # Numbers/random characters injected into a brand name (e.g. paypa1, micros0ft)
    if re.search(r"[a-z]+\d[a-z]*@", sender_lower):
        score += 2
        findings.append(f"Sender address contains numbers mixed into letters (possible spoof): {sender}")

    return score


def check_generic_greeting(text, findings, score):
    text_lower = text.lower()
    generic = ["dear customer", "dear user", "dear valued customer", "dear account holder"]
    if any(g in text_lower for g in generic):
        score += 1
        findings.append("Uses a generic greeting instead of your actual name (common in mass phishing emails)")
    return score


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_email(text, sender=""):
    findings = []
    score = 0

    score = check_urgency_language(text, findings, score)
    score = check_money_bait(text, findings, score)
    score = check_brand_impersonation(text, findings, score)
    score = check_suspicious_links(text, findings, score)
    score = check_sender_address(sender, findings, score)
    score = check_generic_greeting(text, findings, score)

    if score >= 6:
        verdict = "🔴 LIKELY PHISHING"
    elif score >= 3:
        verdict = "🟠 SUSPICIOUS — Be careful"
    else:
        verdict = "🟢 LIKELY SAFE"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings if findings else ["No obvious red flags detected."],
    }


def print_report(subject, sender, text):
    result = analyze_email(text, sender)
    print("=" * 65)
    print(f"Subject : {subject}")
    print(f"Sender  : {sender if sender else '(not provided)'}")
    print("-" * 65)
    print(f"Risk Score : {result['score']}")
    print(f"Verdict    : {result['verdict']}")
    print("Findings:")
    for f in result["findings"]:
        print(f"  - {f}")
    print("=" * 65)
    print()


# ---------------------------------------------------------------------------
# Demo: test on a few sample emails
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    # Sample 1: Obvious phishing email
    print_report(
        subject="Urgent: Verify Your PayPal Account Now",
        sender="paypal-support@paypa1-secure.xyz",
        text="""
        Dear Customer,

        We detected unusual activity on your account. Your account will be
        suspended unless you verify your identity immediately.

        Click here to confirm your identity: http://paypal-secure-login.xyz/verify

        Act now, this link expires today.
        """
    )

    # Sample 2: Normal, safe email
    print_report(
        subject="Team meeting moved to 3 PM",
        sender="hassan.khan@company.com",
        text="""
        Hi Maaz,

        Just a heads up — today's team meeting has been moved from 2 PM to
        3 PM. Same Zoom link as usual. Let me know if that doesn't work for you.

        Thanks,
        Hassan
        """
    )

    # Sample 3: Lottery / money bait scam
    print_report(
        subject="Congratulations! You Have Won $1,000,000",
        sender="claims@lottery-winners.info",
        text="""
        Dear Winner,

        You have won a prize of $1,000,000 in our international lottery.
        To claim your reward, click here: http://192.168.55.21/claim-prize

        This is a limited time offer, contact us immediately with your bank
        transfer details.
        """
    )

    # ---- Try your own email here ----
    print("Now testing a custom email you can edit below:\n")
    my_subject = "Your Amazon account has been locked"
    my_sender = "amazon-security@amaz0n-alerts.top"
    my_text = """
    Dear Customer,

    We noticed unauthorized login attempts on your Amazon account.
    For your security, your account has been temporarily restricted.

    Please confirm your identity here: http://amaz0n-alerts.top/restore-access

    Failure to verify within 24 hours will result in permanent suspension.
    """
    print_report(my_subject, my_sender, my_text)
