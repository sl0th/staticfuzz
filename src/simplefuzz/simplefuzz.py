#!/usr/bin/python

import socket
import commands
import string
import random

def success(mesg):
	return "[\x1b[32m+\x1b[37m] " + mesg

def failure(mesg):
	return "[\x1b[31m-\x1b[37m] " + mesg

def alert(mesg):
	return "[\x1b[33m!\x1b[37m] " + mesg

# builds a random string
def randstring(size=4000):
	return ''.join(random.choice(string.letters + string.digits) for _ in range(size))

# builds n random strings concatenated by ' '
# maxstringsize is the longest an individual string can be generated
def genstrings(n, maxstringsize=4000):
	cat = ""
	for i in range(n): 
		cat += " "
		cat += randstring(random.randint(1, maxstringsize))

	return cat

# reads a message over the socket s until delimiter delim is encountered
def readuntil(s, delim):
        torpat = delim 
        ret = ""

        while len(torpat)>0:
                c = s.read(1)
                if c == torpat[0]:
                        torpat = torpat[1:]    
                else:
                        torpat = delim
                ret += c

        return ret 

# reads an MPD response message in its entirety
# @s : socket our fuzzer is using to connect to MPD
def readmpdresp(s):
	resp = s.read(3)
	if (resp == 'ACK'):
		resp += readuntil(s, '\n')
	elif (resp != 'OK\n'):
		resp += readuntil(s, 'OK\n')
	return resp


def fuzz(s):

	commandlist = commands.commandlist
	s.write("command_list_begin\n")
	while True:
		payload = ""
		for (cmd, mn, mx) in commandlist:
			if cmd in commands.killers:
				continue
			if mx <= 0:
				continue
			print (cmd, mn, mx)
			payload = cmd
			savepayload = payload
			for argn in range(mn, mx+1):
				payload = savepayload + genstrings(argn, 2000)
				print payload
				s.write(payload + "\n")
				s.flush()
				#response = readmpdresp(s)
				#print response

def main():
	s = socket.create_connection(('localhost', 6600))
	s = s.makefile()
	resp = readuntil(s, "\n")
	print success("starting simplefuzzer...")
	print alert("target banner: " + resp);
	fuzz(s)	

main()
