import pandas as pd
from analyze import analyze_email

df = pd.read_csv("dataset.csv")
fn_indices = [470, 387, 498, 463, 497, 447, 453, 499, 418, 413, 441, 361, 363]
fn_files = df.loc[fn_indices]["filename"]

for fname in fn_files:
    filepath = f"emails/phishing/{fname}"
    data = analyze_email(filepath, verbose=False)
    print(f"--- {fname} ---")
    print("Subject:", data.get("subject"))
    print("Body:", (data.get("body") or "")[:400])
    print()