import pandas as pd
import time
import re
import os
import mariadb

def pareslogs(thefile):
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            continue
        yield line


if __name__ == '__main__':
	score = 0
	username = "username" 
	password = "password"	
	reg_xss = "(GET|POST).*(%3C)*(%3E).*(HTTP).[1-9].[1-9]"
	logfile = open("access.log","r")
	regc = re.compile('(?P<ip>.*?) - - \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\d+) "(?P<Referer>.*?)" "(?P<User_agent>.*?)"')
	for line in pareslogs(logfile):
		m = regc.match(line)
		if m is not None:
			ip = m.group('ip')
			time = m.group('time')
			request = m.group('request')
			status = m.group('status')
			size = m.group('size')
			Referer = m.group('Referer')
			User_agent = m.group('User_agent')
			connection = mariadb.connect(user=username, password=password, host="127.0.0.1", port=3306, database="parse")
			cursor = connection.cursor()
			cursor.execute("INSERT INTO logs(ip, time, request, status, size, referer, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)", (ip, time,request, status, size, Referer, User_agent));
			connection.commit()
			if(re.match(".*(%3C)*(%3E).*", request)):  # xss script 
			    score += 2
			if score >= 10:
			    print("Anomaly Detected.")
			    score = 0
		else:
			continue
    
