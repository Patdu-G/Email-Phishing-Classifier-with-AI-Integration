import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

pd.set_option('display.max_columns', None)

df = pd.read_csv("dataset.csv")

print(df.shape)
print(df["label"].value_counts())

X = df.drop(columns=["label", "filename"])
y = df["label"]

print(X[["spf_pass", "dkim_pass", "dmarc_pass"]].corr())

print(df["homograph_domain"].value_counts())

print(df.groupby("label")["num_hard_urgency_keywords"].value_counts().sort_index())
print(df.groupby("label")["num_soft_urgency_keywords"].value_counts().sort_index())

# --- Collapse collinear auth features into one ordinal score ---
X["auth_score"] = X["spf_pass"] + X["dkim_pass"] + X["dmarc_pass"]
X = X.drop(columns=["spf_pass", "dkim_pass", "dmarc_pass"])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print("Train:", X_train.shape, "Test:", X_test.shape)

# --- Scale features so coefficients are comparable ---
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = LogisticRegression(class_weight='balanced', max_iter=1000)
model.fit(X_train_scaled, y_train)

y_pred = model.predict(X_test_scaled)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)
print("Confusion matrix (rows=actual, cols=predicted):")
print(cm)
tn, fp, fn, tp = cm.ravel()
print(f"TN={tn}  FP={fp}  FN={fn}  TP={tp}")
print(f"False negatives (missed phishing): {fn}")
print(f"False positives (legit flagged as phishing): {fp}")

results = X_test.copy()
results["actual"] = y_test.values
results["predicted"] = y_pred
false_negatives = results[(results["actual"] == 1) & (results["predicted"] == 0)]
print(f"\n--- {len(false_negatives)} False Negative rows (phishing predicted as legit) ---")
print(false_negatives)

false_positives = results[(results["actual"] == 0) & (results["predicted"] == 1)]
print(f"\n--- {len(false_positives)} False Positive rows (legit predicted as phishing) ---")
print(false_positives)

# --- Coefficient audit (scaled — magnitudes are now comparable) ---
coefficients = pd.DataFrame({
    "feature": X_train.columns,
    "coefficient": model.coef_[0],
    "abs_coefficient": abs(model.coef_[0])
}).sort_values(by="abs_coefficient", ascending=False)

print("\n--- Feature coefficients (standardized scale) ---")
print(coefficients.to_string(index=False))

# Sanity flags: features with unexpectedly high weight or wrong-sign weight
# (e.g. spf_pass should be negative — pushes toward "legit" — if positive, investigate)
print("\n--- Sign check ---")
for _, row in coefficients.iterrows():
    direction = "→ pushes toward PHISHING" if row["coefficient"] > 0 else "→ pushes toward LEGIT"
    print(f"{row['feature']:30s} {row['coefficient']:+.4f}  {direction}")

print("\n--- Sign check ---")
for _, row in coefficients.iterrows():
    direction = "→ pushes toward PHISHING" if row["coefficient"] > 0 else "→ pushes toward LEGIT"
    print(f"{row['feature']:30s} {row['coefficient']:+.4f}  {direction}")

# --- Per-row contribution breakdown for a specific false positive ---
import numpy as np

row_index = X_test.index.get_loc(43)  # change 43 to inspect a different row
scaled_row = X_test_scaled[row_index]
contributions = scaled_row * model.coef_[0]
contrib_df = pd.DataFrame({
    "feature": X_train.columns,
    "scaled_value": scaled_row,
    "coefficient": model.coef_[0],
    "contribution": contributions
}).sort_values("contribution", key=abs, ascending=False)
print("\n--- Contribution breakdown for row 43 ---")
print(contrib_df.to_string(index=False))
print("Sum of contributions + intercept:", contributions.sum() + model.intercept_[0])    