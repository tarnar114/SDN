from struct import pack
import numpy as np
import csv

packets_csv=np.genfromtxt('data/packets.csv',delimiter=",")
dt_packets=packets_csv[:,0]
sdfp=np.std(dt_packets)

byte_csv=np.genfromtxt('data/bytes.csv',delimiter=",")
dt_bytes=byte_csv[:0]
sdfb=np.std(dt_bytes)

n_ip=np.prod(dt_bytes.shape)
ssip=n_ip//3

sfe=n_ip//3

f1=None
f2=None
with open('data/ipsrc.csv','r') as t1, open ('data/ipdst/csv','r'):
    f1=t1.readlines()
    f2=t2.readlines()
with open('data/intflow.csv','w') as f:
    for line in fileone:
        if line not in filetwo:
            f.write(line)

# Count number of 
with open('data/intflow.csv') as f:
    reader = csv.reader(f, delimiter=",")
    dt = list(reader)
    row_count_nonint = len(dt)

rfip = abs(float(n_ip - row_count_nonint) / n_ip)

headers = ["SSIP", "SDFP", "SDFB", "SFE", "RFIP"]

features = [ssip, sdfp, sdfb, sfe, rfip]

# print(dict(zip(headers, features)))
# print(features)

with open('realtime.csv', 'w') as f:
    cursor = csv.writer(f, delimiter=",")
    cursor.writerow(headers)
    cursor.writerow(features)
    
    f.close()   