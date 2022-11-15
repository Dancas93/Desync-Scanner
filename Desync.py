#!/usr/bin/env python3

import sys
import os
import queue
import threading
from threading import Thread, Lock
import base64
import argparse
import socket
import ssl
import random
from urllib.parse import urlparse, parse_qsl
from http.client import HTTPResponse
from io import BytesIO
from datetime import datetime
import colorama
from colorama import Fore, Style
import csv


num_threads = 40
q = queue.Queue()
lock = Lock()

urls = []
nrTotUrls = 0
nrUrlsAnalyzed = 0
nrErrorUrl = 0


URL = False
timeout = 5
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
debug = False
file = False

__version__ = 'version 0.0.1'

outputFilename = datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
completeFileName = "output/"+outputFilename+".txt"
os.makedirs(os.path.dirname(completeFileName), exist_ok=True)


#Initialize colorama
colorama.init(autoreset=True)

def writeToLog(testo):
    # Open a file with access mode 'a'
    with open(completeFileName, "a") as file_object:
        # Append 'hello' at the end of file
        file_object.write(testo+"\n")

def checkPythonVersion():
	if sys.version_info < (3, 9):
		print("Error: requires Python 3.9.")
		sys.exit(1)

def printAnalyzingMessage():
    lock.acquire()
    print(f"Url Analyzing {nrUrlsAnalyzed}/{nrTotUrls} and we got {nrErrorUrl} error", end='\r')
    lock.release()

def printBanner():
	banner = 'ICAgIF9fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgIF9fX19fX19fICAgIF9fX18gCiAgIC8gX18gXF9fXyAgX19fX19fXyAgX19fX19fICBfX19fXy8gX19fXy8gLyAgIC8gX18gXAogIC8gLyAvIC8gXyBcLyBfX18vIC8gLyAvIF9fIFwvIF9fXy8gLyAgIC8gLyAgIC8gLyAvIC8KIC8gL18vIC8gIF9fKF9fICApIC9fLyAvIC8gLyAvIC9fXy8gL19fXy8gL19fXy8gL18vIC8gCi9fX19fXy9cX19fL19fX18vXF9fLCAvXy8gL18vXF9fXy9cX19fXy9fX19fXy9cX19fXy8gIAogICAgICAgICAgICAgICAgL19fX18vICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA='
	print(base64.b64decode(banner).decode('UTF-8'))
	print(__version__ + " by Dancas")
	print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions")
	print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")


def checkInputParams():
	parser = argparse.ArgumentParser(prog='DesyncCL0', description='Detects HTTP desync CL.0 vulnerabilities.')
	parser.add_argument('-u', '--url', default=False, help='The URL to be checked.')
	#parser.add_argument('-s', '--smuggledrequestline', default='GET /hopefully404 HTTP/1.1', help='Set the smuggled request line (default "GET /hopefully404 HTTP/1.1").')
	parser.add_argument('-t', '--timeout', type=int, default=5, help='Set connection timeout for desync test (default 5).')
	parser.add_argument('-ua', '--user_agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36', help='Set default User-Agent request header (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36").')
	parser.add_argument('-d', '--debug', action=argparse.BooleanOptionalAction, default=False, help='Print debug data.')
	parser.add_argument('-f', '--file', default=False, help='insert file with url to analyze.')
	args = parser.parse_args()
	global URL,timeout,user_agent,debug,file
	URL = args.url
	timeout = args.timeout
	user_agent = args.user_agent
	debug = args.debug
	file = args.file

def loadFiles(file):
    global urls
    global nrTotUrls
    with open(file) as file:
        while line := file.readline():
            url = line.rstrip()
            urls.append(url)
            q.put(str(url)) #multithreading
            nrTotUrls += 1

def check_url(url):
	url_checked = urlparse(url)
	if ((url_checked.scheme != 'http') & (url_checked.scheme != 'https')) | (url_checked.netloc == ''):
		raise argparse.ArgumentTypeError('Invalid %s URL (example: https://www.example.com/path).' % url)
	return url_checked


class FakeSocket():
	def __init__(self, response_bytes):
		self._file = BytesIO(response_bytes)
	def makefile(self, *args, **kwargs):
		return self._file

def send_request(sock, request):
	sock.sendall(request)
	response = b''
	while True:
		try:
			chunk = sock.recv(4096)
			if not chunk:
				break
			else:
				response = response + chunk
				source = FakeSocket(response)
				httpresponse = HTTPResponse(source)
				httpresponse.begin()
				if httpresponse.getheader('Content-Length'):
					CL = int(httpresponse.getheader('Content-Length'))
					body = httpresponse.read(CL)
					if CL == len(body):
						break
					else:
						continue
				elif httpresponse.getheader('Transfer-Encoding'):
					body = httpresponse.read(len(response))
					if b'0\r\n\r\n' in chunk:
						break
					else:
						continue
		except socket.error as err:
			if(debug):
				lock.acquire()
				print('ERROR! Raw Response:', response)
				print(err)
				lock.release()
			else:
				pass
			#exit(1)
	if response == b'':
		pass
		#print('ERROR! Got a blank response from the server.')
		#exit(1)
	elif 'body' not in locals():
		body = b''
	return httpresponse, body

def cl0_check(URL, user_agent, timeout, debug):
	hostname = URL.netloc
	if URL.path == '':
		path = '/'
	else:
		path = URL.path + ('?' + URL.query if URL.query else '')  + ('#' + URL.fragment if URL.fragment else '')


	SRL = 'GET /hopefully404 HTTP/1.1'

	# >>>>> request404
	requestSmuggled = SRL + '\r\n'
	requestSmuggled = requestSmuggled + 'Foo: x'
	requestRoot = 'GET / HTTP/1.1\r\n'
	requestRoot = requestRoot + 'Host: ' + hostname + '\r\n'
	requestRoot = requestRoot + 'User-Agent: ' + user_agent + '\r\n'
	requestRoot = requestRoot + 'Connection: close\r\n'
	requestRoot = requestRoot + '\r\n'
	request404 = requestSmuggled + requestRoot
	if debug:
		print(">>>>> request404")
		print(request404)
		print(">>>>> request404")
	sock = connect(URL, timeout)
	httpresponse404, body404 = send_request(sock, request404.encode('utf-8'))
	if(sock!=None):
		sock.close()
	if debug:
		print(">>>>> httpresponse404")
		print("status404:", httpresponse404.status)
		print("headers404:", httpresponse404.getheaders())
		print("body404:", body404)
		print("<<<<< httpresponse404")
	# <<<<< request404

	# >>>>> requestRoot
	if debug:
		print(">>>>> requestRoot")
		print(requestRoot)
		print("<<<<< requestRoot")
	sock = connect(URL, timeout)
	httpresponseRoot, bodyRoot = send_request(sock, requestRoot.encode('utf-8'))
	if(sock!=None):
		sock.close()
	if debug:
		print(">>>>> httpresponseRoot")
		print("statusRoot:", httpresponseRoot.status)
		print("headersRoot:", httpresponseRoot.getheaders())
		print("bodyRoot:", bodyRoot)
		print("<<<<< httpresponseRoot")
	# <<<<< requestRoot

	# >>>>> requestDesync
	requestDesync = 'POST ' + path + ' HTTP/1.1\r\n'
	requestDesync = requestDesync + 'Host: ' + hostname + '\r\n'
	requestDesync = requestDesync + 'User-Agent: ' + user_agent + '\r\n'
	requestDesync = requestDesync + 'Content-Length: ' + str(len(requestSmuggled)) + '\r\n'
	requestDesync = requestDesync + 'Connection: keep-alive\r\n'
	requestDesync = requestDesync + 'Content-Type: application/x-www-form-urlencoded\r\n'
	requestDesync = requestDesync + '\r\n'
	requestDesync = requestDesync + requestSmuggled
	if debug:
		print(">>>>> requestDesync")
		print(requestDesync)
		print("<<<<< requestDesync")
	sock = connect(URL, timeout)
	httpresponseDesync, bodyDesync = send_request(sock, requestDesync.encode('utf-8'))
	if debug:
		print(">>>>> httpresponseDesync")
		print("statusDesync:", httpresponseDesync.status)
		print("headersDesync:", httpresponseDesync.getheaders())
		print("bodyDesync:", bodyDesync)
		print("<<<<< httpresponseDesync")
	# <<<<< requestDesync

	# >>>>> requestRootSmuggled
	requestRootSmuggled = requestRoot
	if debug:
		print(">>>>> requestRootSmuggled")
		print(requestRootSmuggled)
		print("<<<<< requestRootSmuggled")
	httpresponseRootSmuggled, bodyRootSmuggled = send_request(sock, requestRootSmuggled.encode('utf-8'))
	if(sock!=None):
		sock.close()
	if debug:
		print(">>>>> httpresponseRootSmuggled")
		print("statusRootSmuggled:", httpresponseRootSmuggled.status)
		print("headersRootSmuggled:", httpresponseRootSmuggled.getheaders())
		print("bodyRootSmuggled:", bodyRootSmuggled)
		print("<<<<< httpresponseRootSmuggled")
	# <<<<< requestRootSmuggled

	if httpresponseRootSmuggled.status == httpresponse404.status and httpresponseRootSmuggled.status != httpresponseRoot.status:
		lock.acquire()
		print(URL.netloc)
		#writeToLog(URL.netloc + ' WARNING! Back-end server interpreted the body of the POST request as the start of another request.')
		print(Fore.YELLOW + 'WARNING! Back-end server interpreted the body of the POST request as the start of another request.')
		lock.release()
	elif httpresponseRootSmuggled.status == httpresponseRoot.status and httpresponseRootSmuggled.status == httpresponse404.status and str(httpresponseRootSmuggled.status).startswith('3') and httpresponseRootSmuggled.getheader('Location') != httpresponseRoot.getheader('Location'):
		lock.acquire()
		print(URL.netloc)
		#writeToLog(URL.netloc + ' WARNING! Probably vulnerable due different redirects.')
		print(Fore.GREEN + 'WARNING! Probably vulnerable due different redirects.')
		lock.release()
		if(debug):
			print('httpresponse404', httpresponse404.getheader('Location'))
			print('httpresponseRoot', httpresponseRoot.getheader('Location'))
			print('httpresponseRootSmuggled', httpresponseRootSmuggled.getheader('Location'))
		if 'hopefully404' in httpresponseRootSmuggled.getheader('Location'):
			lock.acquire()
			print(URL.netloc)
			print('httpresponseRootSmuggled contains hopefully404')
			lock.release()
	elif httpresponseRootSmuggled.status == httpresponseRoot.status and httpresponseRootSmuggled.status == httpresponse404.status and str(httpresponseRootSmuggled.status).startswith('3') and httpresponseRootSmuggled.getheader('Location') == httpresponseRoot.getheader('Location'):
		#lock.acquire()
		#print(URL.netloc)
		#writeToLog(URL.netloc + ' WARNING! All responses are redirects to the same location.' + str(httpresponseRootSmuggled.getheaders()))
		#lock.release()
		if(debug):
			print(Fore.YELLOW + 'WARNING! All responses are redirects to the same location.', httpresponseRootSmuggled.getheaders())
			print(Fore.YELLOW + 'Try to debug with an invalid or HEAD method on the smuggled request line.')
	else:
		if(debug):
			print('Not vulnerable.')

def connect(URL, timeout):
	hostname = URL.netloc.split(':')[0]
	if URL.scheme == 'https':
		port = 443 if URL.port is None else URL.port
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		sock = socket.create_connection((hostname, port), timeout)
		ssock = context.wrap_socket(sock, server_hostname=hostname)
		return ssock
	elif URL.scheme == 'http':
		port = 80 if URL.port is None else URL.port
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)
		sock.connect((hostname, port))
		return sock

#TODO:
def launchThreads():
	global num_threads
	global q
	for i in range(num_threads):
		worker = Thread(target=scanUrls).start()
        #worker.start()
	q.join()


def scanUrls():
    global q
    global nrUrlsAnalyzed
    global nrErrorUrl
    while not q.empty():
        #print(threading.get_ident())
        try:
            #checkConnectivity()
            printAnalyzingMessage()
            url = q.get()
            scanUrl(url)
            nrUrlsAnalyzed += 1
        except Exception as e:
            nrErrorUrl += 1
            printAnalyzingMessage()
        q.task_done()
    printAnalyzingMessage()
        

def scanUrl(url):
	#global URL
	if(not url):
		print("You must insert at least an url with -u parameter or a file with -f")
		exit()
	url = check_url(url)
	#print('Testing URL: ' + url.scheme + '://' + url.netloc + url.path + ('?' + url.query if url.query else '')  + ('#' + url.fragment if url.fragment else ''))
	try:
		cl0_check(url, user_agent, timeout, debug)
	except Exception as err:
		#print(str(err))
		pass 

def launchScan():
	if(file):
		loadFiles(file)
		launchThreads()
	else:
		global URL
		scanUrl(URL)  

def main():
	checkPythonVersion()
	printBanner()
	checkInputParams()
	launchScan()


if __name__ == '__main__':
	main()
