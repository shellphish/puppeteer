import logging
l = logging.getLogger('puppeteer.rop.ropchain')

import struct

from ..errors import NoobError

class ROPChain(object):
    def __init__(self, arch, chain=None, expected_length=None):
        '''
        Creates a new ROPChain.
        '''
        self.arch = arch
        self.chain = chain if chain is not None else [ ]
        self.expected_length = expected_length

    def add(self, entry):
        '''
        Adds an entry to the ROP chain. Valid types are:

            int - converted to N bytes, where N is the architecture byte width
            None - left as a default value (probably 0x41414141...)
            str - some string, printed directly. Should be aligned to the byte
                  width.
        '''
        if isinstance(entry, str) and len(entry) % self.arch.bytes != 0:
            raise NoobError("%d-byte ROP entry in a %d-bit architecture!" % (len(entry), self.arch.bytes))

        if len(self.chain) > 0 and isinstance(self.chain[-1], ROPGadget) and self.chain[-1].leave != ROPGadget.LEAVE_RET is not None:
            if isinstance(entry, ROPGadget):
                self.chain[-1].set(next_addr = entry.addr)
            else:
                l.warning("Non-ret ROPGadget followed by a non-gadget")

        self.chain.append(entry)

    def __add__(self, entry):
        '''
        Adds two ROPChains together, or adds something to a ROPChain.
        '''
        if isinstance(entry, ROPChain):
            return ROPChain(self.arch, chain=self.chain+entry.chain, expected_length=self.expected_length)
        else:
            r = ROPChain(self.arch, chain=self.chain, expected_length=self.expected_length)
            r.add(entry)
            return r

    def __radd__(self, entry):
        '''
        Adds two ROPChains together, or adds something to a ROPChain.
        '''
        if isinstance(entry, ROPChain):
            return ROPChain(self.arch, chain=entry.chain+self.chain, expected_length=self.expected_length)
        else:
            r = ROPChain(self.arch, expected_length=self.expected_length)
            r.add(entry)
            r.chain += self.chain
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
        if self.expected_length is not None and self.length() != self.expected_length:
            raise NoobError("size doesn't match!")

        did_ret = True

        s = ""
        for entry in self.chain:
            if isinstance(entry, str):
                s += entry
            elif type(entry) in [ int, long, float ]:
                s += struct.pack(self.arch.struct_fmt, entry)
            elif isinstance(entry, ROPGadget):
                if did_ret:
                    s += struct.pack(self.arch.struct_fmt, entry.addr)

                s += entry.build()
                did_ret = entry.leave == ROPGadget.LEAVE_RET
        return s

    def length(self):
        '''
        Returns the length, in bytes, of the ROP chain.
        '''
        length = 0
        for entry in self.chain:
            if isinstance(entry, str):
                length += len(entry)
            elif type(entry) in [ int, long, float ]:
                length += self.arch.bytes
            elif isinstance(entry, ROPGadget):
                length += entry.length * self.arch.bytes
        return length

    def __len__(self): return self.length()

from .ropgadget import ROPGadget
