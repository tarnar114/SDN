from datetime import datetime
from tkinter import Y
import joblib
from matplotlib.pyplot import axis

import pandas as pd
from sklearn.model_selection import train_test_split

from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import accuracy_score
start = datetime.now()
print('loading dataset')
data = pd.read_csv('data/dataset.csv')

X = data.drop('Class', axis=1)
Y = data['Class']

X_train, X_test, Y_train, Y_test = train_test_split(
    X, Y, test_size=0.2, random_state=0)

scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

classifier = SVC(kernel='linear', random_state=0)
flow_model = classifier.fit(X_train, Y_train)

y_pred = flow_model.predict(X_test)

print("------------------------------------------------------------------------------")
print("confusion matrix")
cm = confusion_matrix(Y_test, y_pred)
cr = classification_report(Y_test, y_pred)

print('classification of the test set/n')
print(y_pred)

print('confusion matrix\n')
print(cm)

print('classification report\n')
print(cr)

acc=accuracy_score(Y_test,y_pred)
print("succes accuracy = {0:.2f} %\n".format(acc*100))

fail=1.0-acc
print("fail accuracy = {0:.2f} %".format(fail*100))


print("------------------------------------------------------------------------------")
end = datetime.now()
print("Training time: ", (end-start)) 

filename='classifier.sav'
joblib.dump(flow_model,filename)
print('model exported')