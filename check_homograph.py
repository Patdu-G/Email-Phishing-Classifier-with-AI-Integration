import pandas as pd

df = pd.read_csv("dataset.csv")
print(df.groupby("label")["homograph_domain"].sum())
print(df["homograph_domain"].sum(), "/ 556 total rows flagged")