#!/usr/bin/python
import os
import re
import sqlite3
conn = sqlite3.connect('database.sqlite')
c = conn.cursor()

c.execute('DROP TABLE IF EXISTS logs');
c.execute('CREATE table IF NOT EXISTS logs (c1 VARCHAR(255), c2 VARCHAR(255), c3 VARCHAR (255), c4 VARCHAR (255))');

stdin,stdout = os.popen2("tail -n 20000 ../access.log | grep /send.php")
#stdin,stdout = os.popen2("tail -n 20000 ../access.log")
stdin.close()
arq = stdout.readlines(); 
stdout.close();


for linha in arq:
    vals = re.findall(r'"([^"]*)"', linha)

    c.execute('INSERT OR IGNORE INTO logs (c1, c2, c3, c4) values (?, ?, ?, ?)', 
    	(vals[0], vals[1], vals[2], vals[3])
    )


print
print('\x1b[6;30;42m' + ' NGINX STATS : access.log latest 10k entries top 30 entries ' + '\x1b[0m')


def byCol(col) :
	print 
	sql = 'SELECT COUNT(*) AS NUM, '+col+', * FROM logs GROUP BY '+col+' ORDER BY NUM DESC LIMIT 20'
	c.execute(sql)
	for row in c:
		print row;

byCol('c1')	
byCol('c2')	
byCol('c3')	
byCol('c4')	
print