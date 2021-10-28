#!/usr/bin/python
import os
import re
shorttable = {}
st = []
arq = []
col = 6 #6 / 10

# stdin,stdout = os.popen2("tail -n 10000 ../access.log")
# stdin.close()
# arq = stdout.readlines(); stdout.close();


dados = os.popen("tail -n 10000 ../access.log")
arq = dados.readlines(); 
dados.close()

#arq.sort(reverse=True)
for linha in arq:
    parts = linha.split(" ")
    if len(parts) > col:
        host = parts[col]
        shorttable[host] = 1 + shorttable.get(host,0)

for s, ss in shorttable.items():
    st.append ([ss, s])
st.sort(reverse=True)

print
print('\x1b[6;30;42m' + ' NGINX STATS : access.log latest 10k entries top 30 entries ' + '\x1b[0m')

for s, ss in st[:30]:
	print (s,ss)

print