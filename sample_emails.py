import os
import random
import shutil

INPUT_FOLDER = "emails_from_gmail"
OUTPUT_FOLDER = "emails_sampled_for_review"
SAMPLE_SIZE = 200

def main():
    random.seed(42)  # reproducible sample
    all_files = os.listdir(INPUT_FOLDER)
    print(f"Found {len(all_files)} total files")

    sample = random.sample(all_files, min(SAMPLE_SIZE, len(all_files)))

    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    for filename in sample:
        shutil.copy(
            os.path.join(INPUT_FOLDER, filename),
            os.path.join(OUTPUT_FOLDER, filename)
        )

    print(f"Copied {len(sample)} randomly sampled files to {OUTPUT_FOLDER}")

if __name__ == "__main__":
    main()