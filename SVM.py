from datetime import datetime
from mimetypes import init
from tkinter import Y
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import accuracy_score

class SVMmodel:
    def __init__(self):
        self.train()
    def predict(self,x):
        x=self.std.transform([x])
        return self.svm.predict(x)
    def train(self):
        start = datetime.now()
        data = pd.read_csv('data/data.csv')

        X = data.iloc[:,:-1]
        Y = data["label"]

        scaler = StandardScaler()
        scaler.fit(X.values)
        X = scaler.transform(X)
        X_train, X_test, Y_train, Y_test = train_test_split(
            X, Y, test_size=0.2, random_state=1,stratify=Y)


        classifier = SVC(kernel='linear', random_state=0).fit(X_train,Y_train)


        self.svm=classifier
        self.std=scaler

