from pwn import *
import subprocess
import os
from utils import *
from file_struct import *

CHALL_NAME = "./"
final = 0
debug = 0

enc = lambda a: a.encode() if isinstance(a, str) else a
sla = lambda a, b: io.sendlineafter(enc(a), enc(b))
snl = lambda a: io.sendline(enc(a))
sna = lambda a, b: io.sendafter(enc(a), enc(b))
snd = lambda a: io.send(enc(a))
rcu = lambda a: io.recvuntil(enc(a), drop=True)
rcv = lambda a: io.recv(enc(a))
rcl = lambda: io.recvline()
p24 = lambda a: p32(a)[:-1]
l64 = lambda a: u64(a.ljust(8, b"\x00"))
l32 = lambda a: u64(a.ljust(4, b"\x00"))
l16 = lambda a: u64(a.ljust(2, b"\x00"))
lin = lambda a: log.info(f"{hex(a)=}")
sen = lambda a: str(a).encode()
mangle = lambda ptr, pos: ptr ^ (pos >> 12)

def debug():
    pid = io.proc.pid
    subprocess.run(["gnome-terminal", "--", "zsh", "-c", "gdb -nx -x ./custom_gdb.py -x g -p " + str(pid)])

libc_path = "./" + subprocess.run("ls | grep -E \"^libc\"", shell=True, capture_output=True).stdout.decode().strip()
ld_path = "./" + subprocess.run("ls | grep -E \"^ld\"", shell=True, capture_output=True).stdout.decode().strip()

exe = context.binary = ELF(CHALL_NAME, checksec=False)
libc = ELF(libc_path, checksec=False)
ld   = ELF(ld_path, checksec=False)

if final == 1:
    io = remote("", 0)
else:
    io = process(CHALL_NAME)



if debug and not final:
    debug()
io.interactive()