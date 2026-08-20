import email
import re
from email.header import decode_header
from email.utils import parseaddr
from bs4 import BeautifulSoup
from urllib.parse import urlparse

import codecs


def _unknown_8bit_search(name):
    if name in ("unknown-8bit", "unknown_8bit"):
        return codecs.lookup("latin-1")
    return None


codecs.register(_unknown_8bit_search)

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "act now", "suspended",
    "click here", "confirm your identity", "limited time",
    "your account has been", "immediately", "security alert",
    "last email", "account is on its way out", "log in within",
    "we miss you", "expire", "final notice", "don't miss",
    "unusual activity", "pending status", "new document",
    "shared with you", "voice message", "delivery", "parcel",
    "mailbox", "incoming mail", "connection error",
    "immediate attention", "password has expired", "cancellation",
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

def _extract_domain(header_value):
    """
    Parse an email header (From, Reply-To, etc.) and return its domain,
    lowercased. Handles the same malformed-header edge case as
    check_display_name_mismatch: headers where parseaddr() fails because
    the "display name" is itself an unquoted email address.
    """
    if not header_value:
        return ""
    _, address = parseaddr(header_value)
    if not address:
        angle_match = re.search(r'<([^<>]+)>', header_value)
        if angle_match:
            address = angle_match.group(1).strip()
    return address.split("@")[-1].lower() if "@" in address else ""

def _root_domain(domain):
    """
    Return the registrable root domain — typically the last two labels
    (e.g. 'discover.pinterest.com' -> 'pinterest.com'). Not fully correct
    for multi-part TLDs like '.co.uk', but good enough for this dataset.
    """
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _domains_related(domain1, domain2):
    """
    True if domain1 and domain2 share the same registrable root domain
    (e.g. 'discover.pinterest.com' and 'reply.pinterest.com' both root to
    'pinterest.com'). Used so Reply-To checks don't flag legitimate
    cross-subdomain mail infrastructure as a mismatch.
    """
    return _root_domain(domain1) == _root_domain(domain2)
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

def check_reply_to_mismatch(sender_header, reply_to_header):
    """
    Flags when Reply-To domain differs from From domain — classic spoofing
    tell where the visible sender looks legitimate but replies route
    elsewhere. Related domains (subdomains of the same organization, e.g.
    'pinterest.com' vs 'reply.pinterest.com') are NOT flagged as mismatches.

    Returns 1 if Reply-To is present AND its domain is unrelated to From's domain.
    Returns 0 if Reply-To is absent, domains match, or domains are related.
    """
    if not reply_to_header:
        return 0

    from_domain = _extract_domain(sender_header)
    reply_to_domain = _extract_domain(reply_to_header)

    if not from_domain or not reply_to_domain:
        return 0

    return 0 if _domains_related(from_domain, reply_to_domain) else 1
def _levenshtein(a, b):
    """Standard edit distance, no external deps."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def check_homograph_domain(actual_domain, max_distance=2, min_domain_length=6):
    """
    Flags sending domains that are suspiciously close (small edit distance)
    to a known brand's legitimate domain but NOT an exact or subdomain
    match — catches lookalike/typosquat domains (e.g. 'paypa1.com',
    'micros0ft-verify.com') that check_display_name_mismatch's brand check
    misses because the display name doesn't mention the brand at all.

    min_domain_length guards against short legit domains (e.g. 'dhl.com',
    7 chars) colliding at edit-distance-2 with unrelated short domains that
    have nothing to do with the brand.

    Returns 1 if actual_domain is within max_distance of some known brand's
    legit domain but isn't that domain (or a subdomain of it), and the legit
    domain being compared against is at least min_domain_length chars.
    Returns 0 otherwise.
    """
    if not actual_domain:
        return 0

    for legit_domains in KNOWN_BRANDS.values():
        for legit in legit_domains:
            if actual_domain == legit or actual_domain.endswith("." + legit):
                return 0  # legitimate match to this brand — never flag
            if len(legit) >= min_domain_length and _levenshtein(actual_domain, legit) <= max_distance:
                return 1

    return 0

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
    reply_to = decode_str(msg["reply-to"])
    if verbose:
        print("Subject:", subject)
        print("From:", sender)
        print("Reply-To:", reply_to)

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

    combined_text_lower = (subject + " " + body).lower()
    found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in combined_text_lower]
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
        "reply_to": reply_to,
        "auth_results": auth_results,
        "display_name_results": display_name_results,
        "num_links": len(links),
        "num_urgency_keywords": len(found_keywords),
        "urgency_keywords_found": found_keywords,
        "num_link_mismatches": mismatch_count,
        "body": body,
        "html_body": html_body,
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
        "reply_to_mismatch": check_reply_to_mismatch(email_data["sender"], email_data["reply_to"]),       
        "homograph_domain": check_homograph_domain(dn["actual_domain"]),
    }
    return features


if __name__ == "__main__":
    files_to_analyze = [
        "emails/phishing/phish_0028.eml",
        "emails/phishing/phish_0144.eml",
        "emails/phishing/phish_0161.eml",
        "emails/legit/eml_2277.eml",
    ]
    for filename in files_to_analyze:
        data = analyze_email(filename, verbose=False)
        features = extract_features(data)
        print(f"\n--- {filename} ---")
        print("From:", data["sender"])
        print("Reply-To:", data["reply_to"])
        print("reply_to_mismatch:", features["reply_to_mismatch"])

    print(check_homograph_domain("paypa1.com"))       # expect 1
    print(check_homograph_domain("paypal.com"))       # expect 0 (exact match)
    print(check_homograph_domain("mail.paypal.com"))  # expect 0 (subdomain)
    print(check_homograph_domain("random-blog.com"))  # expect 0 (too far from any brand)