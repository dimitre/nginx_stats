#!/usr/bin/python

import os
import re
import sqlite3
conn = sqlite3.connect('database.sqlite')
c = conn.cursor()

def drop():
	c.execute('''DROP TABLE logs'''); #file
	c.execute('''DROP TABLE file'''); #file
	c.execute('''DROP TABLE ref'''); #file
def init():    
	c.execute('''create table IF NOT EXISTS logs (file INTEGER, ref INTEGER)''')
	c.execute('''CREATE TABLE IF NOT EXISTS file(id INTEGER PRIMARY KEY,file text UNIQUE)''')
	c.execute('''CREATE TABLE IF NOT EXISTS ref(id INTEGER PRIMARY KEY,ref text UNIQUE)''')

def gather():
	for line in open('../../access.log'):
		parts = line.split(" ")
		c.execute('INSERT OR IGNORE INTO file (file) values (?)', (str(parts[6]),))


		if len(parts) > 10:
			parts[10] = parts[10].strip('\"')
			c.execute('INSERT OR IGNORE INTO ref (ref) values (?)', (str(parts[10]),))
		file_id = ref_id = 0
		c.execute('SELECT id FROM file WHERE file=?', (parts[6],))
		for row in c:
			file_id = row[0]
		
		if len(parts) > 10:
			c.execute('SELECT id from ref WHERE ref=?', (parts[10],))
			for row in c:
				ref_id = row[0]

		sql = "insert OR IGNORE into logs values ('" + str(file_id)  + "', '"+ str(ref_id)  +"')"
		c.execute(sql)
		
def find(table,param):
	sql = "SELECT id from "+table+" WHERE "+table+"='"+param+"'"
	print sql
	c.execute(sql)
	for row in c:
		res = row[0]
		return res
	

def process(table):
	item = {}
	c.execute('SELECT * from '+table)
	for row in c:
		item[row[0]] = row[1]

	sql = "SELECT "+table+",COUNT(*) AS n from logs GROUP BY "+table+" ORDER BY n DESC LIMIT 50" # ORDER BY file DESC LIMIT 130
	c.execute(sql)
	for row in c:
		if row[0] > 0:
			print row[1], item[row[0]]

def finding(table,name,table2):
	ref = {}
	file = {}
	c.execute('SELECT * from ref')
	for row in c:
		ref[row[0]] = row[1]
	c.execute('SELECT * from file')
	for row in c:
		file[row[0]] = row[1]

	fileid = find(table,name)
	if fileid is not None:
		sql = "SELECT "+table+","+table2+",COUNT(*) AS n from logs WHERE file="+str(fileid)+" GROUP BY ref ORDER BY n DESC LIMIT 50" # ORDER BY file DESC LIMIT 130
		print sql
		c.execute(sql)
		for row in c:
			if row[0] > 0:
				print row[2], file[row[0]], ref[row[1]]
	else:
		print 'result is None'

drop()
init()
gather()
process('file')
#process('ref')
#finding('file','/1/tiler-005.jpg')
#finding('file','/swfobject.js','ref')
#finding('file','/jquery/jquery-1.4a1.min.js','ref')
finding('ref', 'http://www.unseenamsterdam.com/users/3410', 'file')
#finding('ref','"http://danielpinheiro.com.br/pasargada/"', 'file')

conn.commit()
c.close()
	
 