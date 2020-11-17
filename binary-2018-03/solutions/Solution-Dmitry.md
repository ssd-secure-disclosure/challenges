# Introduction
It is easy to detect that valid row numbers are 0..15 (thanks to error messages).

“Private Key Encryption” handling routine sets bit 3 (& 8) of number of rows thus allowing access to rows 16..23. Key is stored in rows 18..20. Each row represents 32-bit value.

Encryption is just calculation of pow(msgRow, keyRow, 1<<32)

Fastest method (using timing attack) allows recovering of row value in single pass. Each non-zero bit in exponent requires additional call to decrypt(), that causes sensitive delay.

But due to difficulties in automation of SSH interactive communication I derives each row in 3 steps:
1. Find number of bits if exponent (by counting “Continue Encryption? (y/n)” prompts)
2. Find highest 16 bits of exponent (by stopping encryption 16 bits before its end and brute-forcing 16 bit exponent value)
3. Find complete exponent (by brute-forcing lowest 16 bits)

# Python solution
```python
import sys, subprocess, time
class SSH_beVX(object):
  EMSG = "8. Exit"
  def send_command(self, cmd):
    self.proc.stdin.write(cmd + "\n")
    self.proc.stdin.flush()
    ln = self.proc.stdout.readline()
    assert ln.startswith(cmd)
    self.started = time.clock()
  def read_line(self):
    return self.proc.stdout.readline()
  def read_until(self, msg=EMSG):
    lines = []
    while True:
      lines.append(self.read_line())
      if lines[-1].startswith(msg):
        return lines
  def write_row(self, row, val):
    self.send_command("0")
    self.read_line() # Enter row and number
    self.send_command("%d %d" % (row, val))
    self.read_until() # Please choose your option:
  def read_row(self, row):
    self.send_command("1")
    self.read_line() # Enter row
    self.send_command("%d" % row)
    ln = self.read_line() # Result is
    assert ln.startswith("Result is")
    self.read_until() # Please choose your option:
    return int(ln.split()[-1])
  def measure_crypt(self, keyRow, msgRow=0, val=3):
    self.write_row(msgRow, val)
    self.send_command("6")
    self.read_line() # Enter row of message, row of key
    self.send_command("%d %d" % (msgRow, keyRow))
    exp = 0
    while True:
      ln = self.read_line()
      delta = time.clock() - self.started
      bit = 1 if delta > 0.7 else 0
      exp = (exp*2) + bit
      sys.stderr.write("\r%8X" % exp)
      if not ln.startswith("Continue Encryption? (y/n)"): break
      self.send_command("Y")
    self.read_until() # Please choose your option:
    res = self.read_row(msgRow)
    if res != pow(val, exp, 1<<32):
      exp ^= 1
      if res != pow(val, exp, 1<<32): raise Exception("Can't find key[%d]" % keyRow)
    s = ("%08X" % exp).decode("hex")
    sys.stderr.write("\r%08X [%s]\n" % (exp, s))
    return s
  def __init__(self, host, username, password, port=22):
    args = ["plink", "-l", username, "-pw", password, "-P", "%d" % port, host]
    self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)
def main():
  ssh = SSH_beVX("x.x.x.x", "challenge", "challenge")
  ssh.read_until() # Please choose your option:
  r = [ssh.measure_crypt(keyRow, 0, 7) for keyRow in xrange(18, 21)]
  print "Key is [%s]" % "".join(r) # "beVX Sep 20!"
  ssh.send_command("8")
if __name__=="__main__": main()
```