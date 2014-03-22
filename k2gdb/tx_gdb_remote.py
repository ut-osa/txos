#!/usr/bin/python
import socket
import gdbstub
import pty,tty
import sys,os,select

from termios import *

class tx_gdb_remote:
	def __init__(self, cmd, port):
		self.cmd = cmd
		self.port = port

	def setup(self):
		# start up the child
		pid,fd = pty.fork()

		if pid is 0:
			os.system(self.cmd)
			sys.exit()

		# put the child terminal and the controlling input in raw mode
		new_attr = tcgetattr(fd)
		new_attr[0] &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | ICRNL)
		new_attr[1] &= ~(OPOST)
		new_attr[2] &= ~(CSIZE)
		new_attr[3] &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN)
		tcsetattr(fd, TCSAFLUSH, new_attr)

		self.old_attr = tcgetattr(sys.stdin)
		new_attr = tcgetattr(sys.stdin)
		new_attr[0] &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | ICRNL)
		new_attr[2] &= ~(CSIZE)
		new_attr[3] &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN)
		tcsetattr(sys.stdin, TCSAFLUSH, new_attr)

		# create a socket and accept a connection
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.bind(('', self.port))
		sock.listen(1)

		self.stub = gdbstub.gdbstub(sock, fd)

	def run(self):
		# start the stub
		self.stub.run()

	def cleanup(self):
		tcsetattr(sys.stdin, TCSAFLUSH, self.old_attr)

remote = tx_gdb_remote(sys.argv[1], int(sys.argv[2]))
remote.setup()
sys.stdout = file("k2gdb_log", "w", 0)
try:
	remote.run()
finally:
	remote.cleanup()
