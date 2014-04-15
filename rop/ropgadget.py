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

    def __init__(self, addr, pops=None, length=None, movs=None, sets=(), influences=(), clobbers=(), leave=LEAVE_RET, leave_pos=None):
        '''
        Creates a new ROPGadget. Look at the ROPGadget class docstring for more info.
        '''
        self.addr = addr
        self.pops = { } if pops is None else pops
        self.movs = { } if movs is None else movs
        self.sets = set(sets)
        self.influences = set(influences)
        self.clobbers = set(clobbers)
        self.leave = leave
        self.leave_pos = leave_pos

        if length is None and pops is None:
            self.length = 2
        elif length is None:
            self.length = len(pops) + 1
        else:
            self.length = length

        self.args = [ None ] * self.length

    def __call__(self, *args, **kwargs):
        '''
        Creates a copy of the gadget, with the arguments filled out.
        '''
        c = copy.deepcopy(self)
        for i in args:
            c.args[i] = args[i]

        for i in kwargs:
            c.args[self.pops[i]] = kwargs[i]

        return c

    def build(self, arch=None):
        '''
        Converts the ROPGadget into a string, ready to be written to the
        victim program's memory.
        '''
        s = ""
        for a in self.args:
            if a is None:
                s += '\x41' * arch.bytes
            elif type(a) in [ int, long, float ]:
                s += struct.pack(arch.struct_fmt, a)
            else:
                if len(a) != arch.bytes:
                    raise NoobError("unaligned entry in rop chain?")
                s += a
        return s

class ROPChain(object):
    def __init__(self, arch, chain=None, length=None):
        '''
        Creates a new ROPChain.
        '''
        self.arch = arch
        self.chain = chain if chain is not None else [ ]
        self.length = length

    def add(self, entry):
        '''
        Adds an entry to the ROP chain. Valid types are:

            int - converted to N bytes, where N is the architecture byte width
            None - left as a default value (probably 0x41414141...)
            str - some string, printed directly. Should be aligned to the byte
                  width.
        '''
        if len(entry) != self.arch.bytes:
            raise NoobError("unaligned?")

        self.chain.append(entry)

    def __add__(self, entry):
        '''
        Adds two ROPChains together, or adds something to a ROPChain.
        '''
        if isinstance(entry, ROPChain):
            return ROPChain(self.arch, chain=self.chain+entry.chain, length=self.length)
        else:
            r = ROPChain(self.arch, chain=self.chain, length=self.length)
            r.add(entry)
            return r

    def __iadd__(self, entry):
        '''
        Adds to a ROPChain.
        '''
        if isinstance(entry, ROPChain):
            self.chain += entry.chain
        else:
            self.add(entry)

        return self

    def build(self):
        '''
        Converts the ROPChain to a string, ready to be written to the victim
        program's memory.
        '''
        if self.length is not None and len(self.chain) != self.length:
            raise NoobError("size doesn't match!")

        s = ""
        for entry in self.chain:
            if isinstance(entry, str):
                s += entry
            elif type(entry) in [ int, long, float ]:
                s += struct.pack(self.arch.struct_fmt, entry)
            elif isinstance(entry, ROPGadget):
                s += entry.build(self.arch)
        return s
