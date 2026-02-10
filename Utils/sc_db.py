from pwn import *

context.arch = 'amd64'
context.os = 'linux'

orw = asm('''
.att_syntax
          

          ''')