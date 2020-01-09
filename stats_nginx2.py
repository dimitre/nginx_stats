
# visualizing in plotdevice.io


import codecs
import operator
size(800,800)
def unique(seq, idfun=None):  
    if idfun is None: 
        def idfun(x): return x 
    seen = {} 
    result = [] 
    for item in seq: 
        marker = idfun(item) 
        if marker in seen: continue 
        seen[marker] = 1 
        result.append(item) 
    return result

#print filenames
txt = codecs.open('../access.log', 'r',"utf-8").read()

letras = txt[:11100].split(' ')
unico = unique(letras)
val = []
for u in unico:
	val.append((u, letras.count(u)))
#map(operator.itemgetter(0), val)
#map(operator.itemgetter(1), val)
val2 = sorted(val, key=operator.itemgetter(1))
val2.reverse()
str = ''

max = val2[0][1]
y=0
h=15
val2 = val2[:150]

#import unicodedata
#print unicodedata.name(u'ã')

font("HelveticaNeue", h)
for l,n in val2:
	w = 500 * n / max
	rect (0,y,w,h)
	text(l, w+20, y+h)
	print l
	y += h+1
	#print y
