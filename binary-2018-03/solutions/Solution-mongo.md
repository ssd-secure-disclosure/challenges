# Python solution
```python
import operator
import ctypes, sys, re, os
from pwn import *
from pwnlib.tubes.ssh import *
remote = 1
if not remote:
	conn = ssh(host='192.168.1.5', user='cha1', password='cha1')
else:
	conn = ssh(host='x.x.x.x', user='challenge', password='challenge')
s = conn.shell()
s.sendall = s.send
s.recvuntil("\r\n")
s.recvuntil("8. Exit")
def store(idx, val):
	s.sendall("0\n%d\n%d\n" % (idx, val))
	s.recvuntil("8. Exit")
def get(idx):
	s.sendall("1\n%d\n" % (idx))
	s.recvuntil("Result is ")
	v = int(s.recvuntil("\r\n"))
	s.recvuntil("8. Exit")
	return v
def privateenc(msg_idx, key_idx):
	s.sendall("6\n")
	s.recvuntil("Enter row of message, row of key\r\n")
	s.sendall("%d\n%d\n" % (msg_idx, key_idx))
	s.recvuntil("\n")
	s.recvuntil("\n")
def reset():
	for i in range(16):
		store(i, 0)
def get_key_part(key_idx):
	privateenc(16, key_idx)
	times = 0
	"""
	check the number of bits left in this key part
	"""
	for i in range(32):
		v = s.recvuntil("\r\n").strip()
		#print "<<", v
		if "Continue Encryption" in v:
			s.sendall("y\n")
			s.recvuntil("\n")
			times += 1
		else:
			break
	s.recvuntil("8. Exit")
	print "key %d bits = %d" % (key_idx, times)
	num_bits = times
	"""
	now, get key_part
	keep in mind result is multiplied by itself at every step
	if key bit is 1, we also multiply by 3 (baseval)
	"""
	baseval = 3
	pos = 32 - num_bits - 1
	skip = 0
	cur_val = 1
	key_part = 0
	for i in range(32 - num_bits, 32):
		store(0, baseval)
		privateenc(0, key_idx)
		val_if_1 = ((cur_val * cur_val) * baseval) & 0xFFFFFFFF
		val_if_0 = ((cur_val * cur_val)) & 0xFFFFFFFF
		times = 0
		for i in range(skip + 1):
			v = s.recvuntil("\n").strip()
			s.sendall("y\n")
			s.recvuntil("\n")
		v = s.recvuntil("\n").strip()
		if "Continue" in v:
			s.sendall("n\n")
			s.recvuntil("\n")
		s.recvuntil("8. Exit")
		res = get(0)
		#print "res=", res
		if res not in [val_if_0, val_if_1]:
			print res
			print [val_if_0, val_if_1]
			raise "Fail"
		key_part = (key_part << 1) | (1 if res == val_if_1 else 0)
		cur_val = res
		skip += 1
	print bin(key_part), "%08X" % key_part, ("%08X" % key_part).decode('hex')
for i in range(18, 22):
	get_key_part(i)
s.close()
```