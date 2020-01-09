#!/usr/bin/python

""" Course page lister.  Looks at all file starting with ac and
treats it as an standard web log file. Reports on all domains that
have visited a course description page"""

import os
import re
#from hname import *



class hname:
   def __init__(self,text):
      self.dparts = text.split(".")
      if self.dparts[-1].isdigit():
         self.havename = 0
      else:
         self.havename = 1
   def getShort(self):
      if self.havename:
         if self.dparts[-1] == "uk":
           dpp = self.dparts[-3:]
           if dpp[0] == "demon":
              dpp = self.dparts[-4:]
         else:
            dpp = self.dparts[-2:]
      else:
           dpp = self.dparts[:]
      return ".".join(dpp)


shorttable = {}
st = []

ctable = {}
lookfor = re.compile("GET\s/course/([a-z]+)")


#
for line in open('/usr/local/nginx/logs/access.log').xreadlines():
    
  parts = line.split(" ")
# How much of the name / IP address do we report?
#  host = hname(parts[6])
  host = parts[6]
#  dpsumm = host.getShort()
  dpsumm = host
#  print dpsumm
# Count the host usage and log any course files
#  shorttable[dpsumm] = 1 + shorttable.get(dpsumm,0)
  shorttable[dpsumm] = 1 + shorttable.get(dpsumm,0)
  gotten = lookfor.findall(line)
  if (not gotten): continue
  ctable[dpsumm] = ctable.get(dpsumm,"") + " " + gotten[0]

#shorttable.sort()

for s, ss in shorttable.items():
    st.append ([ss, s])
    #print ss, s
st.sort()
st.reverse()

print st[:30]

def byhits(one,two):
   global shorttable
   return shorttable[two].__cmp__(shorttable[one])

#visitors = ctable.keys()
#visitors.sort(byhits)

#for browser in visitors:
#   print browser,ctable[browser],shorttable[browser]

