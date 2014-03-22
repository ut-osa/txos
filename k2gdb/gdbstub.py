#!/usr/bin/python
import socket
import select
import os,sys
import re

def write_all(fd, str):
	writ = 0
	while writ < len(str):
		writ += os.write(fd, str[writ:])

gdb_register_names = [
	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi",
	"eip",
	"eflags",
	"cs",
	"ss",
	"ds",
	"es",
	"fs",
	"gs",
]

# register numbers to always send as
# part of a stop reply to gdb
stop_registers = [8, 5]

class Blocked:
	pass
class continue_now:
	pass
class gdb_detached:
	pass

def continue_simulation(obj):
	#print "Called continue"
	SIM_post_command(do_continue, None)

# the gdb stub: processes queries from gdb
KDB_PROMPT_STR = r'^\[\d\]kdb> $'
KDB_PROMPT_RE = re.compile(KDB_PROMPT_STR)
class gdbstub:

	LISTENING = 0
	DETACHING = 1
	RUNNING = 2
	STOPPED = 3
	WAIT_PROMPT = 4
	
	def __init__(self, sock, childterm):
		self.sock = sock
		self.state = self.LISTENING
		self.childterm = childterm
		self.buffer = ''
		self.last_line = ''
		self.current_line = ''

		self.command_map = {
			'q':self.process_query,
			'?':self.stop_reason,
			'p':self.read_reg,
			's':self.step,
			'm':self.read_mem,
			'Z':self.set_breakpoint,
			'z':self.remove_breakpoint,
			'c':self.cont,
			'\x03':self.interrupt,
			'D':self.detach,
			'k':self.kill,
			'H':self.empty_reply,
			'v':self.v_packet,
			'vCont?':self.vcont_query,
			'+':self.no_reply
		}

		self.breakpoints = {}
		self.registers = None
		self.last_mem = (0, 0, '')

	def empty_reply(self, body):
		return ''

	def no_reply(self, body):
		return None

	def kill(self, body):
		# remove notification and close socket
		self.conn.close()
		print "Closed"
		self.state = self.DETACHING

	def detach(self, body):
		self.send_command('OK')
		self.kill(body)

	def v_packet(self, body):
		cmd_body = body.split(';', 1)
		if len(cmd_body) > 1:
			command,body = cmd_body
		else:
			command, = cmd_body
			body = ''

		command = 'v' + command
		if self.command_map.has_key(command):
			return self.command_map[command](body)
		else:
			print 'Unsupported command', command
			return ''

	def vcont_query(self, body):
		return 'vCont;c,s'

	def process_query(self, body):
		if body == 'Supported':
			return ''
		#elif body == 'C':
		#	 return 'QC0'
		#elif body == 'Symbol':
		#	 return 'OK'
		else:
			print 'Unsupported query', body
			return ''

	def stop_reason(self, body):
		return 'S02'

	def update_registers(self):
		raw_map = self.kdb_cmd("rd").split()
		self.registers = {}
		for i in range(0, len(raw_map), 3):
			self.registers[raw_map[i]] = int(raw_map[i + 2], 16)

	def clear_reg_mem(self):
		self.registers = None
		self.last_mem = (0, 0, '')

	def _read_reg(self, reg_num):
		if self.registers is None:
			self.update_registers()
		reg_name = gdb_register_names[reg_num]
		if self.registers.has_key(reg_name):
			reg_value = self.registers[reg_name]
		else:
		 	return None
		reg_str = ""
		for i in range(0,4):
			reg_str += "%02x" % (reg_value & 0xFF,)
			reg_value >>= 8
		return reg_str

	def read_reg(self, body):
		reg_str = self._read_reg(int(body, 16))
		if reg_str is None:
			return 'E02'
		return reg_str

	def read_mem(self, body):

		addr,rlen = body.split(',')
		addr = int(addr, 16)
		rlen = int(rlen, 16)
		
		end = addr + rlen
		last_addr,last_end,last_reply = self.last_mem
		if addr >= last_addr and end <= last_end:
			if last_reply[0] != 'E':
				i = 2*(addr - last_addr)
				j = i + 2*rlen
				return last_reply[i:j]
			else:
				return last_reply

		value = self.kdb_cmd("mdr %s %d" % (hex(addr), rlen))
		try:
			n = int(value, 16)
		except:
			value = 'E13'
		self.last_mem = (addr, end, value)
		print "RED:", self.last_mem
		return value

	def set_breakpoint(self, body):
		type,addr,length = body.split(',')
		type = int(type)
		addr = int(addr, 16)
		length = int(length, 16)

		bp_cmds = ['bp 0x%x', 'bpha 0x%x', 'bpha 0x%x DATAW', 'bpha 0x%x DATAR',
			'bpha 0x%x DATAR']
		raw_bp = self.kdb_cmd(bp_cmds[type] % addr)
		pound_idx = raw_bp.find("#")
		space_idx = raw_bp.find(" ", pound_idx)
		bp_no = int(raw_bp[pound_idx+1:space_idx])
		print "BP:", bp_no
		self.breakpoints[addr] = bp_no
		return 'OK'

	def remove_breakpoint(self, body):
		type,addr,length = body.split(',')
		addr = int(addr, 16)
		bp_no = self.breakpoints[addr]
		self.kdb_cmd('bc %d' % bp_no)
		del self.breakpoints[addr]
		return 'OK'

	def breakpoint_hit(self):
		self.update_registers()
		registers_str = ''.join(['%x:%s;' % (reg_num, self._read_reg(reg_num))
				for reg_num in stop_registers])
		self.send_command('T05watch:%x;%s' % \
            (self.registers["eip"],registers_str))

	def cont(self, body):
		assert body == ''
		self.state = self.RUNNING
		self._kdb_cmd('go')
		self.clear_reg_mem()
		return None

	def _interrupt(self):
		os.write(self.childterm, '\r\001')
		self.state = self.WAIT_PROMPT
		self.child_output()
		self.update_registers()
		self.state = self.STOPPED

	def interrupt(self, body):
		self._interrupt()
		registers_str = ''.join(['%x:%s;' % (reg_num, self._read_reg(reg_num))
									for reg_num in stop_registers])
		return 'T02%s' % (registers_str,)

	def step(self, body):
		self.register = None
		self.state = self.RUNNING
		self.kdb_cmd('ss')
		self.clear_reg_mem()
		self.update_registers()
		registers_str = ''.join(['%x:%s;' % (reg_num, self._read_reg(reg_num))
									for reg_num in stop_registers])
		return 'T05watch:%x;%s' % (self.registers["eip"],registers_str)

	def send(self, packet):
		#print "*** Sending"
		sent = self.conn.send(packet)
		#print "*** Sent", packet[:sent]
		return sent

	def recv(self, bufsize):
		if len(self.buffer) == 0:
			self.buffer = self.conn.recv(bufsize)
		recvd = self.buffer[:bufsize]
		self.buffer = self.buffer[bufsize:]
		return recvd

	def put(self, packet):
		self.buffer = packet + self.buffer

	def get_command(self):
		packet_begin = self.recv(1)
		assert len(packet_begin) > 0

		# gdb sends a raw 0x03 for an interrupt, otherwise
		# begins all packets with $
		if packet_begin == '\x03' or packet_begin == '+':
			return packet_begin
		elif packet_begin != '$':
			print packet_begin
			assert False

		last_chunk = self.recv(1024)

		packet_body = ''
		index = None
		while True:
			packet_body += last_chunk
			index = last_chunk.find('#')
			if index > 0 and index < len(last_chunk) - 2:
				break

			last_chunk = self.recv(1024)

		command = packet_body[:index]
		checksum = packet_body[index+1:index+3]

		# checksums are for checking!
		assert self.checksum(command) == checksum

		# return unused data to the buffer and
		# ack the command
		self.put(packet_body[index+3:])
		while self.send('+') != 1:
			pass

		return command

	def checksum(self, cmd):
		csum = sum([ord(i) for i in cmd]) % 256
		return '%02x' % (csum,)

	def send_command(self, cmd):
		# Build and send the command
		command = '$' + cmd + '#' + self.checksum(cmd)
		# print 'Sending command', command
		sent = 0
		while sent < len(command):
			sent += self.send(command[sent:])

		# Blocking receive a single reply packet
		reply = self.recv(1)
		assert reply == '+'

	# The main command processing loop.  Generators
	# turn this into an iterator.  A value is yielded
	# whenever we are out of data.  Simics calls us
	# back when there is new data, the buffer is filled
	# and the iterator is resumed
	def socket_activity(self):
		command = self.get_command()

		token = command[0]
		body = command[1:]

		if self.command_map.has_key(token):
			print 'Running command', command
			reply = self.command_map[token](body)
			print command,"->",repr(reply)
		else:
			print 'Unsupported command', command
			reply = ''

		if reply is not None:
			self.send_command(reply)

	# write out the entire command, and catch the echo
	def _kdb_cmd(self, cmd):
		cmd += '\r'
		echo = ''
		writ = 0
		r_list = [self.childterm]
		w_list = [self.childterm]
		while True:
			r,w,x = select.select(r_list, w_list, [], 0.5)
			if len(r) > 0:
				output = os.read(self.childterm, writ - len(echo))
				print "ECHO", repr(output)
				echo += output
				write_all(1, output)
				if len(echo) >= len(cmd):
					break

			if len(w) > 0:
				writ += os.write(self.childterm, cmd[writ:])
				if writ >= len(cmd):
					w_list = []
				print "WRIT", repr(cmd[:writ])

			if len(r) == 0 and len(w) == 0:
				print "TIMEOUT"
				writ = len(echo)
				w_list = [self.childterm]

		assert echo == cmd
		newline = os.read(self.childterm, 1)
		if newline != '\n':
			print repr(newline)
			assert False
		write_all(1, '\n')
		self.last_line = ''
		self.current_line = ''
		

	# run a command and buffer kdb's output
	def kdb_cmd(self, cmd):
		self._kdb_cmd(cmd)
		self.state = self.WAIT_PROMPT
		self.child_output()
		self.state = self.STOPPED
		return self.prompt_buffer[:self.prompt_buffer.rindex('\n')]

	def human_input(self):
		str = os.read(0, 4096)
		if self.state <= self.RUNNING:
			write_all(self.childterm, str)

	def child_output(self):
		self.prompt_buffer = ''
		while True:
			str = os.read(self.childterm, 4096)

			lastnl = str.rfind('\n')
			if lastnl != -1:
				self.last_line = self.current_line
				self.current_line = str[lastnl+1:]
				prevnl = str.rfind('\n', 0, lastnl)
				if prevnl != -1:
					self.last_line = str[prevnl+1:lastnl]
				else:
					self.last_line += str[:lastnl]
			else:
				self.current_line += str

			print "LAST:",self.last_line
			print "CURR:",self.current_line

			write_all(1, str)

			if self.state is self.WAIT_PROMPT:
				self.prompt_buffer += str

			if KDB_PROMPT_RE.match(self.current_line):
				if self.state is self.WAIT_PROMPT:
					break
				elif self.state is self.RUNNING:
					self.breakpoint_hit()
			if self.state is not self.WAIT_PROMPT:
				break


	def run(self):
		sfile = self.sock.makefile()
		while True:
			r,w,x = select.select([0, self.childterm, sfile], [], [])
			for d in r:
				# input on the terminal, write it to the child
				if d is 0:
					self.human_input()
				elif d is self.childterm:
					self.child_output()
				elif d is sfile:
					if self.state is self.LISTENING:
						self.conn,addr = self.sock.accept()
						sfile = self.conn.makefile()
						self._interrupt()
					elif self.state is self.DETACHING:
						sfile = self.sock.makefile()
						self.state = self.LISTENING
					else:
						self.socket_activity()

