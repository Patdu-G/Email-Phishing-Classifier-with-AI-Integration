import os
from analyze import decode_str, check_display_name_mismatch, _levenshtein, KNOWN_BRANDS
import email

phishing_dir = "emails/phishing"
results = []

for fname in os.listdir(phishing_dir):
    if not fname.endswith(".eml"):
        continue
    path = os.path.join(phishing_dir, fname)
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f)
    sender = decode_str(msg["from"])
    dn = check_display_name_mismatch(sender)
    domain = dn["actual_domain"]
    if not domain:
        continue

    # find closest KNOWN_BRANDS domain
    best_dist = None
    best_match = None
    for legit_domains in KNOWN_BRANDS.values():
        for legit in legit_domains:
            d = _levenshtein(domain, legit)
            if best_dist is None or d < best_dist:
                best_dist = d
                best_match = legit

    results.append((fname, domain, best_match, best_dist))

# sort by closeness — smallest edit distance first
results.sort(key=lambda r: r[3])

print(f"{'file':<25} {'actual_domain':<30} {'closest_brand_domain':<20} distance")
for fname, domain, match, dist in results[:25]:
    print(f"{fname:<25} {domain:<30} {match:<20} {dist}")