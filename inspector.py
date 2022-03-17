import pandas as pd
import joblib

file='classifier.sav'
classifier=joblib.load(file)
data=pd.read_csv('realtime.csv')
res=classifier.predict(data)

with open('.result','w') as f:
    f.write(res[0])