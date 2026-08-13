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

def analyze_email(filename):
    print(f"\n=========== Analyzing: {filename} ===========")

    with open(filename, "rb") as f:
        msg = email.message_from_binary_file(f)

    print("Subject:", decode_str(msg["subject"]))
    print("From:", decode_str(msg["from"]))

    auth_results = check_auth_headers(msg)
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

    print("\n--- Body ---")
    print(body[:500])

    links = re.findall(r'https?://[^\s<>"\']+', body)
    print("\n--- Links found ---")
    for link in links:
        print(link)

    body_lower = body.lower()
    found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]
    print("\n--- Urgency keywords found ---")
    print(found_keywords)

    print("\n--- Link mismatches ---")
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        mismatch_count = 0
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            display_text = a_tag.get_text().strip()
            if "." in display_text and " " not in display_text:
                href_domain = urlparse(href).netloc
                text_domain = display_text.replace("http://", "").replace("https://", "").split("/")[0]
                if href_domain and text_domain and href_domain != text_domain:
                    mismatch_count += 1
                    print(f"MISMATCH: text says '{text_domain}' but link goes to '{href_domain}'")
        print(f"Total mismatches: {mismatch_count}")
    else:
        print("No HTML body found.")


files_to_analyze = ["sample.eml", "sample1.eml"]
for filename in files_to_analyze:
    analyze_email(filename)