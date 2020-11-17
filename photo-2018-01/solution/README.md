# Introduction
The challenge was split into two parts:
1. Finding it
2. Solving it

Finding it wasn’t very hard, the challenge was hidden inside the image, it wasn’t anything fancy, just inside the image you had a zip file appended to the end of the file:

```
wget https://blogs.securiteam.com/wp-content/uploads/2018/01/2018_2.jpg
--2018-01-04 07:XX:XX--  https://blogs.securiteam.com/wp-content/uploads/2018/01/2018_2.jpg
Resolving blogs.securiteam.com... 104.196.190.188
Connecting to blogs.securiteam.com|104.196.190.188|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 84283 (82K) [image/jpeg]
Saving to: ‘2018_2.jpg’
2018_2.jpg 100%[=================================================>]  82.31K   321KB/s    in 0.3s
2018-01-04 07:XX:XX (321 KB/s) - ‘2018_2.jpg’ saved [84283/84283]

$ xxd 2018_2.jpg | tail
000148a0: 0000 e817 0000 0900 1800 0000 0000 0000  ................
000148b0: 0000 fd81 0000 0000 6368 616c 6c65 6e67  ........challeng
000148c0: 6555 5405 0003 b50b 495a 7578 0b00 0104  eUT.....IZux....
000148d0: e803 0000 04e8 0300 0050 4b01 021e 0314  .........PK.....
000148e0: 0000 0008 009b 9021 4c14 3bc1 9d86 0000  .......!L.;.....
000148f0: 009c 0000 0006 0018 0000 0000 0001 0000  ................
00014900: 00b4 817b 0900 0052 4541 444d 4555 5405  ...{...READMEUT.
00014910: 0003 265c 4a5a 7578 0b00 0104 e803 0000  ..&\JZux........
00014920: 04e8 0300 0050 4b05 0600 0000 0002 0002  .....PK.........
00014930: 009b 0000 0041 0a00 0000 00              .....A.....
```

If you binwalk inspect the file you will see:

```
$ binwalk 2018_2.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
81481         0x13E49         Zip archive data, at least v2.0 to extract, compressed size: 2360, uncompressed size: 6120, name: challenge
83908         0x147C4         Zip archive data, at least v2.0 to extract, compressed size: 134, uncompressed size: 156, name: README
84261         0x14925         End of Zip archive
```

This looks really promising now, a ZIP file has been appended to the image, and binwalk tells us it’s located at offset 81481. We can use dd to get the archive.

```
$ dd if=2018_2.jpg of=challenge.zip bs=1 skip=81481
2802+0 records in
2802+0 records out
2802 bytes (2.8 kB, 2.7 KiB) copied, 0.00661634 s, 423 kB/s
```

Binwalk also tells us, there are two files inside the archive (challenge and README). Use unzip to get them.
```
$ unzip challenge.zip
Archive:  challenge.zip
  inflating: challenge
  inflating: README
```

The *readme* is pretty simple, just instructed you to make the challenge ELF binary file spit out text:
```
Make 'challenge' output the following text (without a new line):
Happy New Year! From Beyond Security SSD :)
First correct submission will get 1,000$ USD!
```

From this point the solution varied, our first solver reversed engineered the file and discovered what it does, which basically breaks down to:
```
int main(int argc, char **argv, char **envp)
{
  int ret;
  char filename[9];
  char key[13];
  strcpy(filename, "eapfxlya");
  strcpy(key, "\xFF\x6B\x28\x66\xD6\x35\xDA\x01\x4D\x64\x47\xA3");
  ret = challenge(filename, key);
  return ret;
}
int keyhash(const char *key)
{
  int ret;
  unsigned int i;
  ret = 0;
  for ( i = 0; i < strlen(key); ++i )
    ret = _rotl(key[i] ^ ret, 7);
  return ret;
}
int decode(unsigned int *key, char *out, unsigned int size)
{
  int result;
  int i;
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= size )
      break;
    *key *= 0x8088405;
    out[i] ^= ++*key >> 24;
  }
  return result;
}
int challenge(const char *filename, char *key)
{
  int result;
  int seed;
  unsigned int n;
  FILE *fp;
  char *ptr;
  fp = fopen(filename, "rb");
  if ( fp )
  {
    n = 1;
    seed = keyhash(key);
    while ( n )
    {
      ptr = (char *)malloc(0x200uLL);
      n = fread(ptr, 1uLL, 0x200uLL, fp);
      decode(&seed, ptr, n);
      write(1, ptr, n);
    }
    fclose(fp);
    putchar('\n');
    result = 1;
  }
  else
  {
    puts("file does not exist!");
    result = 0;
  }
  return result;
}
```

The program executes the following actions:
1. Open an encrypted file named “eapfxlya” (this can be confirmed with strace)
2. Generate a 32-bit key based on “\xFF\x6B\x28\x66\xD6\x35\xDA\x01\x4D\x64\x47\xA3” (see function keyhash)
3. Read the contents of the opened file
4. Decode it with XOR/ADD/MUL/SHR tricks (see function decode)

The keyhash function is pretty straight-forward so let’s have a closer look at the decode function. 

It’s purpose is to generate a sequence of 32-bit numbers based on a linear congruential generator (aka *predictive* pseudo number generator) which takes a precomputed hash for seed. 

Each number of this sequence is then shifted right and used as a 8-bit xor-mask on every byte in the file stream. 

In conclusion, this program can be used to decode and encode any file in a symmetric way. So let’s use the happy new year string “Happy New Year! From Beyond Security SSD :)” and feed it into the reversed program.

```
$ echo -ne "Happy New Year! From Beyond Security SSD :)" > eapfxlya
$ ./challenge > tmp
$ dd if=tmp of=eapfxlya bs=43 count=1 # don't forget, it's without a new line
$ ./challenge
Happy New Year! From Beyond Security SSD :)
```
Congratulations to: **Alexandre** for solving the challenge first (within 2 hours of posting it online).
A few other solutions we received included a brute forcing code (a cool one from **Tukan**):
```
root@ubuntu-512mb-ams2-01:~# cat solver.py
import sys
def reversit(inp, checksum=0xf5f6103f):
    out = ''
    for c in inp:
        checksum *= 0x08088405
        checksum &= 2**32-1
        checksum += 1
        outc = ord(c) ^ ((checksum) >> 24)
        out += chr(outc)
    return out
winner = reversit('Happy New Year! From Beyond Security SSD :)' + '\x1b' + 'P')
sys.stdout.write(winner)
root@ubuntu-512mb-ams2-01:~# python solver.py > eapfxlya
root@ubuntu-512mb-ams2-01:~# ./challenge
```
