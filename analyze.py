import email
import re
from email.header import decode_header

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

with open("sample1.eml", "rb") as f:
    msg = email.message_from_binary_file(f)

print("Subject:", decode_str(msg["subject"]))
print("From:", decode_str(msg["from"]))

if msg.is_multipart():
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            body = part.get_payload(decode=True).decode(errors="ignore")
            break
else:
    body = msg.get_payload(decode=True).decode(errors="ignore")

print("\n--- Body ---")
print(body[:500])

links = re.findall(r'https?://[^\s<>"\']+', body)
print("\n--- Links found ---")
for link in links:
    print(link)

URGENCY_KEYWORDS = [
    "urgent", "verify your account", "act now", "suspended",
    "click here", "confirm your identity", "limited time",
    "your account has been", "immediately", "security alert",
    "last email", "account is on its way out", "log in within",
    "we miss you", "expire", "final notice", "don't miss"
]
body_lower = body.lower()
found_keywords = [kw for kw in URGENCY_KEYWORDS if kw in body_lower]

print("\n--- Urgency keywords found ---")
print(found_keywords)