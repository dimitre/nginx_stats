#!/usr/bin/python

#200.171.11.99 - - [09/Dec/2009:01:45:37 -0200] "GET /1/camera-0657.gif HTTP/1.1" 200 13082 "http://dmtr.org/camerasonica/" "Mozilla/5.0 (Windows; U; Windows NT 5.1; pt-BR; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)"
import os
import re
shorttable = {}
st = []
#10 - referer / 6 = file
col = 10

ctable = {}
for line in open('../access.log'):
	parts = line.split(" ")
#    print parts, len(parts)
	if len(parts) > col:
		host = parts[col]
		shorttable[host] = 1 + shorttable.get(host,0)

for s, ss in shorttable.items():
	st.append ([ss, s])
st.sort(reverse=True)

print
print('\x1b[6;30;42m' + ' NGINX STATS : access.log top 50 entries ' + '\x1b[0m')

#for s, ss in st[:150]:
for s, ss in st[:50]:
	print s,ss
print 
