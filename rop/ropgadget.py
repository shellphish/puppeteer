import copy
import struct

from ..errors import NoobError

class ROPGadget(object):
    '''
    A ROPGadget is a callable object that you can use to build ROP chains.
    Here's a sample usage:

        # 0xc001: pop rbx; mov eax, 3; ret
        POP_RBX = ROPGadget(0xc001, pops={'rbx':0}, clobbers={'eax'})

        # 0xd473: call rsi
        CALL_RSI = ROPGadget(0xd473)

        # 0xf4c7: mov ebx, ecx; pop r11; pop r12; pop r13; jmp r11
        CRAZY = ROPGadget(0xf4c7, movs={'ebx': 'ecx'}, pops={'r11':0, 'r12':1,
                          'r13':2, 'r14':3}, leave=LEAVE_JMP, leave_pos=1)

        chain = ROPChain(arch=amd64)
        chain += ROP_RBX(rbx = 0x1337)
        chain += CALL_RSI()
        chain += CRAZY(next=0x41414141)
        chain.build()
    '''

    LEAVE_JUMP = 'LEAVE_JUMP'
    LEAVE_RET = 'LEAVE_RET'
    LEAVE_CALL = 'LEAVE_CALL'

    def __init__(self, arch, addr, pops=None, length=None, movs=None, clobbers=(), leave=LEAVE_RET, leave_pos=None):
        '''
        Creates a new ROPGadget.

            @param arch: the architecture of the binary
            @param addr: the address of the gadget
            @param pops: a dictionary { 'reg_name': position } of registers that are
                         popped. The position is their relative position in the rop
                         chain (i.e., 0 is the first one that's popped).
            @param length: the length of the rop chain, in architecture-sized words.
                           Can be automatically determined if omitted.
            @param movs: a dictionary { 'reg_name': 'reg_name' } of registers that the
                         gadget moves into each other.
            @param clobbers: a sequence ( 'reg_name', 'reg_name' ) of registers that
                             the gadget clobbers.
            @param leave: the type of exit from the gadget (LEAVE_RET, LEAVE_CALL,
                          LEAVE_JUMP).
            @param leave_pos: the position in the gadget where the next address should
                              be put. By default, the end.
        '''
        self.addr = addr
        self.pops = { } if pops is None else pops
        self.movs = { } if movs is None else movs
        self.clobbers = set(clobbers)
        self.leave = leave
        self.leave_pos = leave_pos
        self.arch = arch

        self.length = len(self.pops) if length is None else length
        self.args = [ None ] * self.length

    def set(self, *args, **kwargs):
        for i,a in enumerate(args):
            self.args[i] = a

        for i in kwargs:
            if i == 'next_addr':
                self.args[self.leave_pos] = kwargs[i]
            else:
                self.args[self.pops[i]] = kwargs[i]

    def __call__(self, *args, **kwargs):
        '''
        Creates a copy of the gadget, with the arguments filled out.
        '''
        c = copy.deepcopy(self)
        c.set(*args, **kwargs)
        return c

    def build(self):
        '''
        Converts the ROPGadget into a string, ready to be written to the
        victim program's memory.
        '''
        s = ""
        for a in self.args:
            if a is None:
                s += '\x00' * self.arch.bytes
            elif type(a) in [ int, long, float ]:
                s += struct.pack(self.arch.struct_fmt, a)
            else:
                if len(a) != self.arch.bytes:
                    raise NoobError("unaligned entry in rop chain?")
                s += a
        return s

    def __add__(self, other):
        r = ROPChain(self.arch)
        r.add(self)
        r.add(other)
        return r

    def __radd__(self, other):
        r = ROPChain(self.arch)
        r.add(other)
        r.add(self)
        return r

    def __mul__(self, n):
        r = ROPChain(self.arch)
        for _ in range(n):
            r += self()
        return r

from .ropchain import ROPChain
