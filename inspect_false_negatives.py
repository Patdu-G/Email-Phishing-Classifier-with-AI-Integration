import os
from analyze import analyze_email

LEGIT_DIR = "emails/legit"
PHISHING_DIR = "emails/phishing"

# Paste the row indices from your False Negatives table here
FN_INDICES = [360, 467, 358, 494, 495, 450, 460, 444, 410, 438, 496, 415, 384, 417]

def build_filename_index():
    """Recreate the same file order build_dataset.py used, so DataFrame
    row indices map back to the correct filename."""
    filenames = []
    for folder in [LEGIT_DIR, PHISHING_DIR]:
        for fname in os.listdir(folder):
            filenames.append(os.path.join(folder, fname))
    return filenames

def main():
    filenames = build_filename_index()

    for idx in FN_INDICES:
        if idx >= len(filenames):
            print(f"Row {idx}: out of range, skipping")
            continue

        filepath = filenames[idx]
        try:
            data = analyze_email(filepath, verbose=False)
            dn = data["display_name_results"]
            print(f"\nRow {idx}: {filepath}")
            print(f"  Sender header:   {data['sender']}")
            print(f"  Display name:    {dn['display_name']}")
            print(f"  Actual domain:   {dn['actual_domain']}")
            print(f"  Matched brand:   {dn['matched_brand']}")
        except Exception as e:
            print(f"Row {idx}: {filepath} -> ERROR: {e}")

if __name__ == "__main__":
    main()