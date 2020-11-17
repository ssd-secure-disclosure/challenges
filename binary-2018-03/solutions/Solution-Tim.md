# Introduction
The “encryption” routine operates on 1 bit of the key at a time, modifying an internal ongoing value each step. If the bit is a zero then this value is squared. If the bit is a one then the value is squared and then further multiplied by the value of the “message” that is selected to encrypt.

Because you can stop the encryption at any point, you can encrypt progressively more of the message, allowed each bit to be extracted by comparing the result with the result for the previous number of bits.

Script output:
```
[+] Connecting to x.x.x.x on port 22: Done
[+] Opening new channel: 'shell': Done
[*] Bit 0 result: 0x1
[*] Key: 0
[*] Bit 1 result: 0x11
[*] Key: 01
[*] Bit 2 result: 0x1331
....
[*] Bit 28 result: 0xb11e13b1
[*] Key: 01100010011001010101011001011
[*] Bit 29 result: 0x60ffc061
[*] Key: 011000100110010101010110010110
[*] Bit 30 result: 0x91cfa4c1
[*] Key: 0110001001100101010101100101100
```

# Python solution
```python
#!/usr/bin/env python2
# beVX Challenge 1 exploit script
# - timpwn
import pwn          # pip install pwn
import logging
remote = True
# pwn.context.log_level = logging.DEBUG
def set_value(row, value):
    r.sendline("0")
    r.sendline(str(row))
    r.sendline(str(value))
    r.readuntil(prompt)
def get_value(row):
    r.sendline("1")
    r.readline()
    r.sendline(str(row))
    r.readuntil("Result is ")
    response = r.readline()
    value = int(response)
    r.readuntil(prompt)
    return value
def encrypt(message_row, key_row, bit_count):
    r.sendline("6")
    r.readline()
    r.sendline(str(message_row))
    r.sendline(str(key_row))
    continue_prompt = "Continue Encryption? (y/n)"
    r.readuntil(continue_prompt)
    r.readline()
    for i in range(bit_count):
        r.sendline("y")
        response = r.readline().strip()
        # The remote system echoes our input back
        if response == "y":
            response = r.readline().strip()
        if response != continue_prompt:
            pwn.log.debug("No more encryption at bit {}".format(i))
            r.readuntil(prompt)
            return
    r.sendline("n")
    r.readuntil(prompt)
def decode_key_row(row):
    result = ""
    previous_value = 1
    # Get data out for incremental encryption key bits
    p = pwn.log.progress("Reading row {}".format(row))
    for bit in range(0, 32):
        # Encrypt 0x11 using the key in the row specified
        p.status("Getting bit {}".format(bit))
        multiplier = 0x11
        set_value(0, multiplier)
        encrypt(0, row, bit)
        v = get_value(0)
        pwn.log.debug("Bit {} result: 0x{:x}".format(bit, v))
        # See if our multiplier has been used, which indicates that
        # the key has a "1" in this position
        previous_squared = previous_value * previous_value
        if v == previous_squared & 0xffffffff:
            result += "0"
        elif v == (previous_squared * multiplier) & 0xffffffff:
            result += "1"
        elif v == previous_value:
            # This means that we've gone past the end of the key,
            # so now we know that the first N bits were zeroes
            break
        else:
            pwn.log.warn("Unexpected value!")
            result += "?"
        pwn.log.debug("Progress: " + result)
        previous_value = v
    # Add the zeroes that we didn't get to see at the start of the key
    result = ("0" * (32-len(result))) + result
    p.success("Got row, value: " + result)
    return result
def connect():
    if remote:
        ssh = pwn.ssh(user="challenge",
                      host="x.x.x.x",
                      password="challenge")
        r = ssh.shell()
        prompt = "8. Exit\r\n"
    else:
        r = pwn.process("./cha1")
        prompt = "8. Exit\n"
    return (r, prompt)
r, prompt = connect()
r.readuntil(prompt)
# We can get rows 18-20 ok, after which no encryption cycles are possible -
# this is most likely because the rows are all zeroes.
rows_bits = list()
for row in range(18, 21):
    partial_key = decode_key_row(row)
    rows_bits.append(partial_key)
# Pad out and combine the key parts
combined = ""
for r in rows_bits:
    padded = ("0" * (32 - len(r))) + r
    print "Row value:", hex(int(padded, 2))
    combined += "{:04x}".format(int(padded, 2))
pwn.log.info("Key: " + repr(combined.decode("hex")))
```
