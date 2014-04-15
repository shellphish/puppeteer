import struct

from ..errors import NoobError
from . import ROPGadget

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
