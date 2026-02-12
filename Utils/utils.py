import subprocess
import os
from pwn import *


def get_rand_null(n):
    rand_null_tab = []
    cwd = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    rnt = process(["./rand_null", str(n)])
    for i in range(n):
        rand_null_tab.append(int(rnt.recvuntil(b'\n')[:-1]))
    rnt.close()
    os.chdir(cwd)
    return rand_null_tab

def get_rand_time_null(n):
    rand_null_tab = []
    cwd = os.getcwd()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    rnt = process(["./rand_time_null", str(n)])
    for i in range(n):
        rand_null_tab.append(int(rnt.recvuntil(b'\n')[:-1]))
    rnt.close()
    os.chdir(cwd)
    return rand_null_tab
    

class Prog():
    pid = 0
    og = []
    def setpid(self, id):
        self.pid = id

    progname = b""
    libcname = b""
    code_base = 0
    libc_base = 0
    heap_base = 0

    maptab = []
    def getmap(self):
        res = subprocess.check_output(["/bin/cat", "/proc/"+str(self.pid)+"/maps"])
        res = res.splitlines()
        self.progname = res[0].split()[5]
        self.code_base = int(res[0].split()[0].split(b"-")[0], 16)
        for l in res:
            self.maptab.append(l)
            if b"[heap]" in l and self.heap_base == 0:
                self.heap_base = int(l.split()[0].split(b"-")[0], 16)
            if b"libc" in l and self.libc_base == 0:
                self.libcname = l.split()[5]
                self.libc_base = int(l.split()[0].split(b"-")[0], 16)

        
    def getog(self):
        res = subprocess.check_output(["one_gadget", self.libcname])
        res = res.splitlines()
        tabres = []
        for l in res:
            if b"0x" in l and b"(" in l and b")" in l:
                at = int(l.split()[0], 16)
                tabres.append(at + self.libc_base)
        return tabres
