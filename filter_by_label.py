import os
import email
from email import policy

INPUT_FOLDER = "emails_from_gmail"

def get_labels(filepath):
    with open(filepath, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    raw = msg.get("X-Gmail-Labels", "")
    return [label.strip() for label in raw.split(",")] if raw else []

def main():
    total = 0
    spam_trash = 0
    likely_legit = 0
    unlabeled = 0

    skip_list_path = "skip_these.txt"
    keep_list_path = "review_these.txt"

    with open(skip_list_path, "w", encoding="utf-8") as skip_f, \
         open(keep_list_path, "w", encoding="utf-8") as keep_f:

        for filename in sorted(os.listdir(INPUT_FOLDER)):
            filepath = os.path.join(INPUT_FOLDER, filename)
            total += 1
            try:
                labels = get_labels(filepath)
            except Exception as e:
                print(f"  Failed to read {filename}: {e}")
                continue

            if not labels:
                unlabeled += 1
                keep_f.write(f"{filename}\t(no labels)\n")
                continue

            if "Spam" in labels or "Trash" in labels:
                spam_trash += 1
                skip_f.write(f"{filename}\t{labels}\n")
            else:
                likely_legit += 1
                keep_f.write(f"{filename}\t{labels}\n")

    print(f"Total: {total}")
    print(f"Spam/Trash (skip): {spam_trash}")
    print(f"Likely legit (review): {likely_legit}")
    print(f"Unlabeled (review): {unlabeled}")
    print(f"\nSee {keep_list_path} for the shortlist to review, {skip_list_path} for what got excluded.")

if __name__ == "__main__":
    main()