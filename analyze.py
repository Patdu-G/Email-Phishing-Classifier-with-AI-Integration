import email
import re
from email.header import decode_header
from bs4 import BeautifulSoup
from urllib.parse import urlparse

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "act now", "suspended",
    "click here", "confirm your identity", "limited time",
    "your account has been", "immediately", "security alert",
    "last email", "account is on its way out", "log in within",
    "we miss you", "expire", "final notice", "don't miss"
]

def check_auth_headers(msg):
    """Extract SPF/DKIM/DMARC verdicts from Authentication-Results header."""
    auth_header = msg.get("Authentication-Results", "")
    
    results = {}
    for mechanism in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"
    
    return results

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
        "num_links": len(links),
        "num_urgency_keywords": len(found_keywords),
        "urgency_keywords_found": found_keywords,
        "num_link_mismatches": mismatch_count,
    }

def extract_features(email_data):
    """Convert analyze_email()'s output dict into a numeric feature vector."""
    auth = email_data["auth_results"]

    features = {
        "spf_pass": 1 if auth["spf"] == "pass" else 0,
        "dkim_pass": 1 if auth["dkim"] == "pass" else 0,
        "dmarc_pass": 1 if auth["dmarc"] == "pass" else 0,
        "num_links": email_data["num_links"],
        "num_urgency_keywords": email_data["num_urgency_keywords"],
        "num_link_mismatches": email_data["num_link_mismatches"],
    }
    return features


files_to_analyze = [
    "emails/legit/legit_sample.eml",
    "emails/legit/legit_sample1.eml",
]
for filename in files_to_analyze:
    data = analyze_email(filename)
    features = extract_features(data)
    print("\n--- Feature vector ---")
    print(features)