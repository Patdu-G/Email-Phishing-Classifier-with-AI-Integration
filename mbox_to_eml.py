import mailbox
import os
import sys


def convert(mbox_path, output_folder):
    if not os.path.exists(mbox_path):
        print(f"Error: {mbox_path} not found.")
        return

    os.makedirs(output_folder, exist_ok=True)
    mbox = mailbox.mbox(mbox_path)

    count = 0
    errors = 0

    for i, message in enumerate(mbox):
        try:
            filename = os.path.join(output_folder, f"eml_{i+1:04d}.eml")
            with open(filename, "wb") as f:
                f.write(message.as_bytes())
            count += 1
        except Exception as e:
            errors += 1
            print(f"  Skipped message {i+1}: {e}")

    print(f"\nDone. Wrote {count} .eml files to {output_folder}")
    if errors:
        print(f"{errors} messages failed to convert.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python mbox_to_eml.py path/to/Mail.mbox output_folder")
        sys.exit(1)

    mbox_path = sys.argv[1]
    output_folder = sys.argv[2]
    convert(mbox_path, output_folder)