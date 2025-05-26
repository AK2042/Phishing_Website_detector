import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

df = pd.read_csv("archive/phishing.csv")
df = df.drop(columns=["Index"])
X = df.drop(columns=["class"])
y = df["class"].replace({-1: 0, 1: 1})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

with open("phishing_detector.pkl", "wb") as f:
    pickle.dump(clf, f)

print("Model saved as phishing_detector.pkl")
