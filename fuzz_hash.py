# -*- coding: utf-8 -*-
from pydbg import *
from pydbg.defines import *
from ctypes import *
import httplib, mimetypes, mimetools, urllib2, cookielib
import optparse
from operator import itemgetter
import os
import sys
import utils
import random
import threading
import shutil
import time
import pickle
import hashlib
import re
#exe_path = "C:\Program Files\GRETECH\GomPlayer\GOM.exe"	   #Target program
#exe_path = "C:\Program Files\Hnc\Hwp80\Hwp.exe"	   #Target program



cj = cookielib.CookieJar()
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
urllib2.install_opener(opener)

class file_fuzzer:
	def __init__(self,target_program,sample_folder):
		self.exe_path		   = target_program		# 대상 프로그램 전체 경로
		self.sample_folder	  = sample_folder		 # 변조할 샘플들이 있는 폴더
		self.ext				= ""					# target format
		self.copyfile		   = "test"				# target copy
		self.runtime			= 4					 # 실행시간
		self.iteration		  = 0					 # 프로그램 실행 횟수를 저장할 변수
		self.mutate_key		 = {}					# mutate 정보를 저장할 딕셔너리
		self.pid				= None				  # pid   를 저장할 변수
		self.in_accessv_handler = False				 # AV 핸들러 플래그
		self.dbg				= None				  # dbg
		self.running			= False				 # 실행 플래그
		self.stream			 = None
		self.crash_bin		  = None
		self.crash_data		 = None
		self.bad_char = ["\x00","\x41","\xff","\x0c","\xAA"]
		self.bad_vector = [ [os.urandom(4),os.urandom(4),os.urandom(4),os.urandom(4),os.urandom(4),"\x00\x00\x00\x00","\xff\xff\xff\xff",],
		["A"*5,"A"*17,"A"*33,"A"*65,"A"*129,"A"*257,"A"*513,"A"*1024,"A"*2049,"A"*4097,"A"*8193,"A"*12288,],
		["%99n","%s%p%x%d",".1024d","%.2049d","%n%n","%p%p","%x%x","%d%d","%s%s","%99999999999s","%08x","%%20d","%%20n","%%20x","%%20s","%#0123456x%08x%x%s%p%d%n%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%","%s"*129,"%x"*257,],
		["\x3f\xff","\xff\x3f","\x7f\xff","\xff\x7f","\x80\x00","\x00\x80","\xfe\xff","\xff\xfe",],
		["\x00\x00\x01\x00","\x00\x01\x00\x00","\x00\x00\x10\x00","\x00\x01\x00\x00","\x00\x00\x01\x00","\x00\x10\x00\x00","\x3f\xff\xff\xff","\xff\xff\xff\x3f","\x7f\xff\xff\xfe","\xfe\xff\xff\x7f","\x7f\xff\xff\xff","\xff\xff\xff\x7f","\x80\x00\x00\x00","\x00\x00\x00\x80","\xff\xff\xff\xfe","\xfe\xff\xff\xff",]]

	def fuzz( self ):
		while 1:
			if not self.running:

				self.iteration += 1
				try:
					file_list = os.listdir(self.sample_folder)				  # Made the list
				except:
					print "[-] %s folder does not exist." % self.sample_folder
					return
				list_length = len(file_list)
				self.targetfile = file_list[random.randint(0,list_length-1)]	# Target file Select

				fd = open(self.sample_folder+"/%s" % self.targetfile, "r+b")	# Target file Open(r+b)
				self.ext = self.targetfile[-4:]								 # Save the Target file EXT
				self.stream = fd.read()										 # Save the Target file Stream
				fd.close()
				self.mutate_file()											  # Mutate Target file

				try:
					self.dbg.terminate_process()
				except:
					pass

				#dbg_thread start
				pydbg_thread = threading.Thread(target=self.start_debugger)
				pydbg_thread.setDaemon(0)
				pydbg_thread.start()

				counter = 0
				while self.pid == None:
					if counter < 5:
						time.sleep(1)
						counter = counter+1
						if counter >=5:
							break
				if self.pid == None:
					print "[-] Fuck...! back"
				#	continue
				#time.sleep(1)

				#monitor_thread start
				monitor_thread = threading.Thread(target=self.monitor_debugger)
				monitor_thread.setDaemon(0)
				monitor_thread.start()
			else:
				time.sleep(1)

#########################################################################
#######				  Fuzz.Start debugger					 ########
#########################################################################
	def start_debugger(self):
		print "[-] String index : %5d " % self.iteration,
		self.running = True
		self.dbg	 = pydbg()
		self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION,self.check_accessv)
		pid = self.dbg.load(self.exe_path, "--play " + "C:\\Users\\Administrator\\Desktop\\TV_FILE_FUZZER-master\\" + self.copyfile+self.ext)

		self.pid = self.dbg.pid
		self.dbg.run()

		if self.pid == None:
			return

#########################################################################
#######				Fuzz.Monitor debugger					 ########
#########################################################################
	def monitor_debugger(self):
		print " Monitoring... ",
		#지정된 시간만큼 sleep하고, process를 종료시킨다.
		counter = 0
		while counter < self.runtime:
			time.sleep(1)
			print counter,
			counter += 1
		print
		time.sleep(1)

		if self.in_accessv_handler != True:
			time.sleep(1)
			try:
				self.dbg.terminate_process()
			except:
				pass
			self.pid = None
			self.running = False
		else:
			pass
		self.pid = None
		self.running = False

	def check_accessv(self,dbg):
		# crash 폴더 생성
		try:
			os.mkdir("crash")
		except:
			pass
		print "\n[+++++++++++++++++++++++++++++]"
		print "[+] Crash : ",
		self.in_accessv_handler = True
		self.crash_bin		  = utils.crash_binning.crash_binning()
		self.crash_bin.record_crash(dbg)
		self.crash_data		 = self.crash_bin.crash_synopsis()

		# crash file을 식별하기 위해서 EIP부분을 덤프뜨고, 파일이름에 추가시켜주기 위한 부분
		# crash file에 EIP와 번호, 포맷을 저장해서 후에 확인하기 편하게 만듬.
		eipoff = self.crash_data.find("EIP")		   # Crash log에서 EIP 부분을 찾음
		eaxoff = self.crash_data.find("EAX")		   # Crash log에서 EAX 부분을 찾음
		eip	= self.crash_data[eipoff+5:eipoff+13]   # Crash가 발생하였을 때의 EIP를 구함.

		# 동일한 Crash가 발생하였을 때 중복 저장을 막기 위해 eip를 기반으로 Hash를 만듬
		hashdump = hashlib.md5(eip)
		hashdump = hashdump.hexdigest()
		print "EIP = %s & hash = %s" % (eip,hashdump),

		# 나중에 진짜 DB 연동
		hashDB_fd = open('hash_DB.txt','r')
		hashDB_data = hashDB_fd.read()
		hashDB_fd.close()
		# hashDB에 hash가 없을 때(새로운 crash일 때 Crash,log,pickle 파일을 저장함)
		if not bool(re.search(hashdump,hashDB_data)):
			try:
				hash_fd = open('hash_DB.txt','a')
				hash_fd.write("EIP = %s & hash = %s & exe_path = %s & ext = %s \n" % (eip,hashdump,self.exe_path,self.ext))
				hash_fd.close()
			except:
				print "[-] %s file does not exist." % "hash_DB.txt"
			# Save the Mutate log
			crash_log_path = "crash\\crash - %s [ %d ] [%s].txt" % (eip, self.iteration, self.targetfile)
			crash_fd = open(crash_log_path,"w")
			crash_fd.write("target Prog = %s \n" % self.exe_path)
			crash_fd.write(self.crash_data)
			crash_fd.close()

			# Save the Mutate pickle
			mutate_dump_path = "crash\\crash - %s [ %d ] [%s].dump" % (eip, self.iteration, self.targetfile)
			mutate_fd = open(mutate_dump_path,"w")
			pickle.dump(self.mutate_key, mutate_fd)
			mutate_fd.close()

			# Copy the crash file
			crash_path = "crash\\crash - %s [ %d ] [%s]%s" % (eip, self.iteration, self.targetfile, self.ext)
			shutil.copy(self.copyfile+self.ext ,crash_path)
			orinal_path = self.sample_folder+ "\\" + self.targetfile



			orinal_path = os.getcwd() + "\\" + orinal_path
			crash_path = os.getcwd() + "\\" + crash_path
			crash_log_path = os.getcwd() + "\\" + crash_log_path
			mutate_dump_path = os.getcwd() + "\\" + mutate_dump_path
			self.crash_data = "target Prog = %s \n %s" % (self.exe_path , self.crash_data)
			#self.upload(orinal_path, crash_path, self.crash_data, mutate_dump_path)


		else:
			print "\n[-] same Crash hash : %s " % hashdump
		print "[+++++++++++++++++++++++++++++]"

		self.in_accessv_handler = False
		self.pid = None

		try:
			self.dbg.terminate_process()
		except:
			pass
		return DBG_EXCEPTION_NOT_HANDLED

###########################################################################
#######				Fuzz.Mutate Target file					 ########
###########################################################################
	def mutate_file( self ):
		copy_fd = open(self.copyfile+self.ext + "1", "w+b")
		copy_fd.write(self.stream)
		copy_fd.close()
		print self.copyfile + self.ext

		passs = "C:\\Users\\Administrator\\Desktop\\TV_FILE_FUZZER-master\\"

		os.system("tmp\\radamsa.exe " +passs+ self.copyfile+self.ext + "1"+ " " + "> " +passs+ self.copyfile+self.ext)

		return

###########################################################################
########							Web!! 							#######
###########################################################################
	def post_multipart(self,host, selector, fields, files):
		content_type, body = self.encode_multipart_formdata(fields, files)
		headers = {'Content-Type': content_type,
				'Content-Length': str(len(body))}
		r = urllib2.Request("http://%s%s" % (host, selector), body, headers)
		return urllib2.urlopen(r).read()

	def encode_multipart_formdata(self,fields, files):
		BOUNDARY = mimetools.choose_boundary()
		CRLF = '\r\n'
		L = []
		for (key, value) in fields:
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"' % key)
			L.append('')
			L.append(value)
		for (key, filename) in files:
			L.append('--' + BOUNDARY)
			L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
			L.append('Content-Type: %s' % self.get_content_type(filename))
			L.append('')
			L.append(self.get_file_content(filename))
		L.append('--' + BOUNDARY + '--')
		L.append('')
		body = CRLF.join(L)
		content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
		return content_type, body

	def get_content_type(self,filename):
		return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

	def get_file_content(self,filename):
		file = open(filename, 'rb')
		content = file.read()
		file.close
		return content
	def upload(self,sample, mutate, context, info):
		self.post_multipart("hacklab.kr", "/fuzz/report.html", [['context', context]], [['sample', sample], ['mutate', mutate], ['info', info]])


def main():
	parser = optparse.OptionParser("python %prog "+ "-t <target Program> -s <sample folder>")
	parser.add_option('-t', dest='target_program',type='string',help='specify target Profram Pull Path')
	parser.add_option('-s', dest='sample_folder',type='string',help='specify sample folder name')
	(options, args) = parser.parse_args()
	target_program = options.target_program
	sample_folder = options.sample_folder
	if( (target_program == None) | (sample_folder == None)):
		print '[-] You must specify a target file and target Program and file extension'
		print '[-] python filename.py -h '
		exit(0)
	print "[ * ] Simple File Fuzzer "
	fuzzer = file_fuzzer(target_program,sample_folder)
	fuzzer.fuzz()

if __name__ == '__main__':
	main()
