import os
from analyze import analyze_email

for folder, label in [("emails/legit", "legit"), ("emails/phishing", "phishing")]:
    total = 0
    missing_header = 0
    for filename in os.listdir(folder):
        filepath = os.path.join(folder, filename)
        try:
            data = analyze_email(filepath, verbose=False)
            total += 1
            if data["auth_results"]["spf"] == "none" and data["auth_results"]["dkim"] == "none":
                missing_header += 1
        except Exception:
            pass
    print(f"{label}: {missing_header}/{total} files have NO auth header at all")