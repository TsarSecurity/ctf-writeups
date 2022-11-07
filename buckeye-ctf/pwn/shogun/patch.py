#!/usr/bin/env python3
from pwn import *
elf = ELF('./shogun')

#Nulify alarm function
elf.asm(elf.symbols['usleep'], 'ret')
elf.save('./shogun-patched')