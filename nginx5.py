#!/usr/bin/python
import os
import re
shorttable = {}
st = []
arq = []
col = 6 #6 / 10

stdin,stdout = os.popen2("tail -n 15000 access.log")
stdin.close()
arq = stdout.readlines(); stdout.close();

#arq.sort(reverse=True)
for linha in arq:
    parts = linha.split(" ")
    if len(parts) > col:
        host = parts[col]
        shorttable[host] = 1 + shorttable.get(host,0)

for s, ss in shorttable.items():
    st.append ([ss, s])
st.sort(reverse=True)

for s, ss in st[:80]:
    print s,ss

