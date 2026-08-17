import os
import shutil

SOURCE = "emails_sampled_for_review"
DEST = "emails/legit"

def main():
    os.makedirs(DEST, exist_ok=True)
    copied = 0
    for filename in os.listdir(SOURCE):
        shutil.copy(os.path.join(SOURCE, filename), os.path.join(DEST, filename))
        copied += 1
    print(f"Copied {copied} files to {DEST}")

if __name__ == "__main__":
    main()