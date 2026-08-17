import os
import sys
sys.stdout.reconfigure(encoding='utf-8')
import email
from email import policy


FOLDER = "emails_sampled_for_review"

def main():
    files = sorted(os.listdir(FOLDER))
    for filename in files:
        filepath = os.path.join(FOLDER, filename)
        try:
            with open(filepath, "rb") as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            sender = msg.get("From", "(no sender)")
            subject = msg.get("Subject", "(no subject)")
            print(f"{filename}\t{sender}\t{subject}")
        except Exception as e:
            print(f"{filename}\tERROR: {e}")

if __name__ == "__main__":
    main()