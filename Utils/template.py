from pwn import *
import subprocess
from utils import *
from file_struct import *




def debug():
    pid = io.proc.pid
    subprocess.run(["gnome-terminal", "--", "zsh", "-c", "gdb -nx -x ~/Desktop/Utils/custom_gdb.py -x g -p " + str(pid)])
def sla(a, b):
    res = io.recvuntil(a)
    print("[+] RECEIVED :")
    print(str(res))
    print("[+] SEND :")
    print(b)
    io.sendline(b)
def sl(a):
    print("[+] SEND :")
    print(a)
    io.sendline(a)
def rcu(a):
    res = io.recvuntil(a)
    print("[+] RECEIVED :")
    print(res)
    return res

#s1 = ssh(host=host, user=user, keyfile=key)
io = process("")
prog = Prog()
prog.setpid(io.proc.pid)
prog.getmap()


debug()
io.interactive()   