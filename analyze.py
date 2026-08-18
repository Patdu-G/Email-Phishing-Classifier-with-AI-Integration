import email
import re
from email.header import decode_header
from email.utils import parseaddr
from bs4 import BeautifulSoup
from urllib.parse import urlparse


URGENCY_KEYWORDS = [
    "urgent", "verify your account", "act now", "suspended",
    "click here", "confirm your identity", "limited time",
    "your account has been", "immediately", "security alert",
    "last email", "account is on its way out", "log in within",
    "we miss you", "expire", "final notice", "don't miss"
]

# Map of brand keyword -> legitimate domain(s) for that brand.
# Add to this list as you find more commonly-spoofed brands in your dataset.
KNOWN_BRANDS = {
    "paypal":    ["paypal.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com"],
    "apple":     ["apple.com", "icloud.com"],
    "amazon":    ["amazon.com"],
    "google":    ["google.com", "gmail.com"],
    "netflix":   ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase":     ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "irs":       ["irs.gov"],
    "usps":      ["usps.com"],
    "fedex":     ["fedex.com"],
    "dhl":       ["dhl.com"],
    "linkedin":  ["linkedin.com"],
    "facebook":  ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
}

_EMAIL_LIKE_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Generic support/authority titles used by senders who aren't impersonating
# any specific brand, e.g. "Help Center", "IT ADMIN", "Mail Delivery System".
GENERIC_AUTHORITY_TERMS = [
    "help center", "help desk", "helpdesk", "mail delivery system",
    "mail server", "it admin", "it support", "support team",
    "account team", "security team", "customer service",
    "tracking-update", "tracking update", "delivery notification",
    "system notification", "billing department", "admin team",
    "service team", "notification",
]


def check_auth_headers(msg):
    """Extract SPF/DKIM/DMARC verdicts from Authentication-Results header."""
    auth_header = msg.get("Authentication-Results", "")
    
    results = {}
    for mechanism in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"
    
    return results


def check_display_name_mismatch(sender_header):
    """
    Given a raw 'From' header string (e.g. 'PayPal Support <security@paypa1-verify.com>'),
    detect display-name spoofing. Catches "quiet" phishing that has no urgency
    language and no link mismatches, but is impersonating a brand in the From field.

    Returns a dict with:
      - brand_mismatch: 1 if display name claims a known brand but the sending
        domain doesn't match that brand's real domain(s)
      - embedded_address_mismatch: 1 if the display name itself contains an
        email-looking string that differs from the actual From address
      - display_name / actual_address / actual_domain / matched_brand: parsed
        values, kept for debugging/inspection (not used as model features)
    """
    display_name, actual_address = parseaddr(sender_header or "")

    # parseaddr returns ('', '') on some malformed-but-common spoofing headers,
    # e.g. "billing@microsoft.com <spoofed@evil-domain.ru>" — where the display
    # name is itself an unquoted email address. Fall back to manual parsing.
    if not actual_address and sender_header:
        angle_match = re.search(r'<([^<>]+)>', sender_header)
        if angle_match:
            actual_address = angle_match.group(1).strip()
            display_name = sender_header[:angle_match.start()].strip()

    display_name_lower = display_name.lower()
    actual_domain = actual_address.split("@")[-1].lower() if "@" in actual_address else ""

    # --- Brand impersonation check ---
    brand_mismatch = 0
    matched_brand = None
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in display_name_lower:
            matched_brand = brand
            if not any(actual_domain == d or actual_domain.endswith("." + d) for d in legit_domains):
                brand_mismatch = 1
            break  # stop at first brand match

    # --- Embedded address spoofing check ---
    embedded_address_mismatch = 0
    embedded_match = _EMAIL_LIKE_RE.search(display_name)
    if embedded_match:
        embedded_address = embedded_match.group(0).lower()
        if embedded_address != actual_address.lower():
            embedded_address_mismatch = 1

    return {
        "display_name": display_name,
        "actual_address": actual_address,
        "actual_domain": actual_domain,
        "matched_brand": matched_brand,
        "brand_mismatch": brand_mismatch,
        "embedded_address_mismatch": embedded_address_mismatch,
    }


def check_generic_authority_sender(display_name):
    """
    Flags display names that use a generic authority/support title instead
    of a real, identifiable brand or person — a common quiet-phishing pattern
    that doesn't impersonate any specific company (e.g. 'Help Center',
    'IT ADMIN', 'Mail Delivery System').
    """
    name_lower = (display_name or "").lower()
    return 1 if any(term in name_lower for term in GENERIC_AUTHORITY_TERMS) else 0


def check_suspicious_local_part(actual_address, min_length=20, min_digits=8):
    """
    Flags addresses where the local part (before the @) is unusually long
    and digit-heavy — a hallmark of auto-generated spam/phishing infra
    (e.g. 'noreply02707838318855032302@...').
    """
    if not actual_address or "@" not in actual_address:
        return 0
    local_part = actual_address.split("@")[0]
    digit_count = sum(c.isdigit() for c in local_part)
    return 1 if (len(local_part) >= min_length and digit_count >= min_digits) else 0


def decode_str(s):
    if s is None:
        return ""
    parts = decode_header(s)
    decoded = ""
    for text, encoding in parts:
        if isinstance(text, bytes):
            decoded += text.decode(encoding or "utf-8", errors="ignore")
        else:
            decoded += text
    return decoded


def analyze_email(filename, verbose=True):
    if verbose:
        print(f"\n=========== Analyzing: {filename} ===========")

    with open(filename, "rb") as f:
        msg = email.message_from_binary_file(f)

    subject = decode_str(msg["subject"])
    sender = decode_str(msg["from"])
    if verbose:
        print("Subject:", subject)
        print("From:", sender)

    auth_results = check_auth_headers(msg)
    if verbose:
        print("Auth results (SPF/DKIM/DMARC):", auth_results)

    display_name_results = check_display_name_mismatch(sender)
    if verbose:
        print("Display-name check:", display_name_results)

    body = ""
    html_body = None
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and not body:
                body = part.get_payload(decode=True).decode(errors="ignore")
            if part.get_content_type() == "text/html" and not html_body:
                html_body = part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    if verbose:
        print("\n--- Body ---")
        print(body[:500])

    links = re.findall(r'https?://[^\s<>"\']+', body)
    if verbose:
        print("\n--- Links found ---")
        for link in links:
            print(link)

    body_lower = body.lower()
    found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    if verbose:
        print("\n--- Urgency keywords found ---")
        print(found_keywords)

    if verbose:
        print("\n--- Link mismatches ---")
    mismatch_count = 0
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            display_text = a_tag.get_text().strip()
            if "." in display_text and " " not in display_text:
                href_domain = urlparse(href).netloc
                text_domain = display_text.replace("http://", "").replace("https://", "").split("/")[0]
                if href_domain and text_domain and href_domain != text_domain:
                    mismatch_count += 1
                    if verbose:
                        print(f"MISMATCH: text says '{text_domain}' but link goes to '{href_domain}'")
    else:
        if verbose:
            print("No HTML body found.")
    if verbose:
        print(f"Total mismatches: {mismatch_count}")

    return {
        "filename": filename,
        "subject": subject,
        "sender": sender,
        "auth_results": auth_results,
        "display_name_results": display_name_results,
        "num_links": len(links),
        "num_urgency_keywords": len(found_keywords),
        "urgency_keywords_found": found_keywords,
        "num_link_mismatches": mismatch_count,
    }


def extract_features(email_data):
    """Convert analyze_email()'s output dict into a numeric feature vector."""
    auth = email_data["auth_results"]
    dn = email_data["display_name_results"]

    features = {
        "spf_pass": 1 if auth["spf"] == "pass" else 0,
        "dkim_pass": 1 if auth["dkim"] == "pass" else 0,
        "dmarc_pass": 1 if auth["dmarc"] == "pass" else 0,
        "num_links": email_data["num_links"],
        "num_urgency_keywords": email_data["num_urgency_keywords"],
        "num_link_mismatches": email_data["num_link_mismatches"],
        "brand_mismatch": dn["brand_mismatch"],
        "embedded_address_mismatch": dn["embedded_address_mismatch"],
        "generic_authority_sender": check_generic_authority_sender(dn["display_name"]),
        "suspicious_local_part": check_suspicious_local_part(dn["actual_address"]),
    }
    return features


if __name__ == "__main__":
    files_to_analyze = [
        "emails/legit/legit_sample.eml",
        "emails/legit/legit_sample1.eml",
    ]
    for filename in files_to_analyze:
        data = analyze_email(filename)
        features = extract_features(data)
        print("\n--- Feature vector ---")
        print(features)