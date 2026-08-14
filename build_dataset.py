import os
import csv
from analyze import analyze_email, extract_features

LEGIT_DIR = "emails/legit"
PHISHING_DIR = "emails/phishing"
OUTPUT_CSV = "dataset.csv"

def build_dataset():
    rows = []
    errors = []

    for folder, label in [(LEGIT_DIR, 0), (PHISHING_DIR, 1)]:
        filenames = os.listdir(folder)
        print(f"Processing {len(filenames)} files from {folder} (label={label})...")

        for filename in filenames:
            filepath = os.path.join(folder, filename)
            try:
                data = analyze_email(filepath, verbose=False)
                features = extract_features(data)
                features["label"] = label
                rows.append(features)
            except Exception as e:
                errors.append((filepath, str(e)))

    if not rows:
        print("No rows were built — check your folders and paths.")
        return

    fieldnames = list(rows[0].keys())
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nWrote {len(rows)} rows to {OUTPUT_CSV}")
    print(f"  Legit (0): {sum(1 for r in rows if r['label'] == 0)}")
    print(f"  Phishing (1): {sum(1 for r in rows if r['label'] == 1)}")

    if errors:
        print(f"\n{len(errors)} files failed to process:")
        for filepath, err in errors[:10]:
            print(f"  {filepath}: {err}")
        if len(errors) > 10:
            print(f"  ...and {len(errors) - 10} more")

if __name__ == "__main__":
    build_dataset()