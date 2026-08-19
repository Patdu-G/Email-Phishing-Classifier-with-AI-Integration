import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv("dataset.csv")

print(df.shape)
print(df["label"].value_counts())

X = df.drop(columns=["label", "filename"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("Train:", X_train.shape, "Test:", X_test.shape)

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

model = LogisticRegression(class_weight='balanced')
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
print("Confusion matrix (rows=actual, cols=predicted):")
print(cm)
tn, fp, fn, tp = cm.ravel()
print(f"TN={tn}  FP={fp}  FN={fn}  TP={tp}")
print(f"False negatives (missed phishing): {fn}")

# Pull out the actual missed phishing rows for inspection
results = X_test.copy()
results["actual"] = y_test.values
results["predicted"] = y_pred
false_negatives = results[(results["actual"] == 1) & (results["predicted"] == 0)]

print(f"\n--- {len(false_negatives)} False Negative rows (phishing predicted as legit) ---")
print(false_negatives)

coefficients = pd.DataFrame({
    "feature": X_train.columns,
    "coefficient": model.coef_[0]
}).sort_values(by="coefficient", key=abs, ascending=False)

print(coefficients)