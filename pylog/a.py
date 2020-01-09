import apachelog, sys

# Format copied and pasted from Apache conf - use raw string + single quotes
format = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'

p = apachelog.parser(format)

for line in open('../access1.log'):
    try:
       data = p.parse(line)
    except:
       sys.stderr.write("Unable to parse %s" % line)
    print data['%b']