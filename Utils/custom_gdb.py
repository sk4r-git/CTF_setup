import gdb

class GetHeap(gdb.Command):
    def __init__(self):
        super(GetHeap,  self).__init__("gh", gdb.COMMAND_USER)
    def _get_heap(slef):
        res = gdb.execute("info proc map", to_string=True)
        for line in res.splitlines():
            if "[heap]" in line:
                heap_address = line.split()[0]
                gdb.execute("set $hat = " + heap_address)
    def complete(self, text, word):
        return gdb.COMPLETE_SYMBOL
    def invoke(self, args, from_tty):
        self._get_heap()
GetHeap()

gdb.execute("gh")

class GetCode(gdb.Command):
    def __init__(self):
        super(GetCode,  self).__init__("gc", gdb.COMMAND_USER)
    def _get_code(slef):
        res = gdb.execute("info proc map", to_string=True)
        for line in res.splitlines():
            if "0x" in line:
                code_address = line.split()[0]
                gdb.execute("set $cat = " + code_address)
                break
    def complete(self, text, word):
        return gdb.COMPLETE_SYMBOL
    def invoke(self, args, from_tty):
        self._get_code()
GetCode()

gdb.execute("gc")