from pwn import *
import subprocess


class FileStruct:
    #utils 
    pid = 0
    at = 0
    #flags
    magic = 0xfbad0000
    unbuff = 0x2
    nr = 0x4
    nw = 0x8
    curr = 0x800
    app = 0x1000

    #struct
    flag = magic
    rptr = 0
    rend = 0
    rbase = 0
    wbase = 0
    wptr = 0
    wend = 0
    bbase = 0
    bend = 0
    sbase = 0
    backbase  = 0
    send = 0
    mark = 0
    chain = 0
    fileno = 0
    flags2 = 0
    old_off = 0
    cur_col = 0
    vo = 0
    shortb = 0
    lock = 0
    off = 0
    code = 0
    wide = 0
    flist = 0
    fbuf = 0
    pad = 0
    mod = 0
    unused = 0
    vtable = 0

    def from_bytes(self, raw_bytes):
        self.flag = u64(raw_bytes[0:8])
        self.rptr = u64(raw_bytes[8:16])
        self.rend = u64(raw_bytes[16:24])
        self.rbase = u64(raw_bytes[24:32])
        self.wbase = u64(raw_bytes[32:40])
        self.wptr = u64(raw_bytes[40:48])
        self.wend = u64(raw_bytes[48:56])
        self.bbase = u64(raw_bytes[56:64])
        self.bend = u64(raw_bytes[64:72])
        self.sbase = u64(raw_bytes[72:80])
        self.backbase = u64(raw_bytes[80:88])
        self.send = u64(raw_bytes[88:96])

        self.mark = u64(raw_bytes[96:104])
        self.chain = u64(raw_bytes[104:112])
        self.fileno = u32(raw_bytes[112:116])
        self.flags2 = u32(raw_bytes[116:120])
        self.old_off = u64(raw_bytes[120:128])

        self.cur_col = u32(raw_bytes[128:132])
        self.vo = u16(raw_bytes[132:134])
        self.shortb = u16(raw_bytes[134:136])

        self.lock = u64(raw_bytes[136:144])
        self.off = u64(raw_bytes[144:152])
        self.code = u64(raw_bytes[152:160])
        self.wide = u64(raw_bytes[160:168])
        self.flist = u64(raw_bytes[168:176])
        self.fbuf = u64(raw_bytes[176:184])
        self.pad = u64(raw_bytes[184:192])
        self.mod = u32(raw_bytes[192:196])
        self.unused = raw_bytes[196:216]
        self.vtable = u64(raw_bytes[216:224])

    def to_bytes(self):
        res = b""
        res += p64(self.flag)
        res += p64(self.rptr)
        res += p64(self.rend)
        res += p64(self.rbase)
        res += p64(self.wbase)
        res += p64(self.wptr)
        res += p64(self.wend)
        res += p64(self.bbase)
        res += p64(self.bend)
        res += p64(self.sbase)
        res += p64(self.backbase)
        res += p64(self.send)
        res += p64(self.mark)
        res += p64(self.chain)
        res += p32(self.fileno)
        res += p32(self.flags2)

        res += p64(self.old_off)
        res += p32(self.cur_col)
        res += p16(self.vo)
        res += p16(self.shortb)
        res += p64(self.lock)
        res += p64(self.off)
        res += p64(self.code)
        res += p64(self.wide)
        res += p64(self.flist)
        res += p64(self.fbuf)
        res += p64(self.pad)
        res += p32(self.mod)
        res += self.unused
        res += p64(self.vtable)
        return res
    
    def setpid(self, id):
        self.pid = id

    def setat(self, at):
        self.at = at

    def exec(self, at):
        self.flag &= 0xffff0000
        self.rptr = 0
        self.wptr = 0
        self.wend = 0
        self.bbase = 0
        self.bend = 0
        self.rend = 0
        self.lock = self.at + 0x10

        self.wide = self.at - 0x10
        self.rbase = 0
        self.wbase = 0

        self.unused = b"\x00"*12 + p64(self.at)
        self.chain = at        



    def pretty(self):
        fields = [
            ("flag", self.flag),
            ("rptr", self.rptr),
            ("rend", self.rend),
            ("rbase", self.rbase),
            ("wbase", self.wbase),
            ("wptr", self.wptr),
            ("wend", self.wend),
            ("bbase", self.bbase),
            ("bend", self.bend),
            ("sbase", self.sbase),
            ("backbase", self.backbase),
            ("send", self.send),
            ("mark", self.mark),
            ("chain", self.chain),
            ("fileno", self.fileno),
            ("flags2", self.flags2),
            ("old_off", self.old_off),
            ("cur_col", self.cur_col),
            ("vo", self.vo),
            ("shortb", self.shortb),
            ("lock", self.lock),
            ("off", self.off),
            ("code", self.code),
            ("wide", self.wide),
            ("flist", self.flist),
            ("fbuf", self.fbuf),
            ("pad", self.pad),
            ("mod", self.mod),
            ("vtable", self.vtable),
        ]

        print("==== FILE STRUCT ====")
        for name, val in fields:
            if isinstance(val, int):
                print(f"{name:10} : 0x{val:016x}")
            else:
                print(f"{name:10} : {val}")
        print("=====================")