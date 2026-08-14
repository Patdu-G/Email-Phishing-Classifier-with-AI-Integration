"""
split_mbox.py

Splits a single .mbox file (e.g. downloaded from the Nazario Phishing Corpus)
into individual .eml files, ready to feed into analyze_email().

Usage:
    python split_mbox.py path/to/phishing-2022.mbox --out emails/phishing --limit 200

Args:
    mbox_path   Path to the .mbox file (extension doesn't matter, e.g. .txt works too)
    --out       Output folder for the individual .eml files (default: emails/phishing)
    --limit     Max number of messages to extract (default: 200)
"""

import mailbox
import os
import argparse


def split_mbox(mbox_path, out_dir, limit):
    os.makedirs(out_dir, exist_ok=True)

    mbox = mailbox.mbox(mbox_path)

    count = 0
    skipped = 0
    for msg in mbox:
        if count >= limit:
            break
        try:
            raw_bytes = msg.as_bytes()
        except Exception:
            skipped += 1
            continue

        out_path = os.path.join(out_dir, f"phish_{count:04d}.eml")
        with open(out_path, "wb") as f:
            f.write(raw_bytes)
        count += 1

    print(f"Extracted {count} messages to '{out_dir}'")
    if skipped:
        print(f"Skipped {skipped} messages that failed to parse")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split an mbox file into individual .eml files")
    parser.add_argument("mbox_path", help="Path to the .mbox file")
    parser.add_argument("--out", default="emails/phishing", help="Output folder (default: emails/phishing)")
    parser.add_argument("--limit", type=int, default=200, help="Max number of messages to extract (default: 200)")
    args = parser.parse_args()

    split_mbox(args.mbox_path, args.out, args.limit)