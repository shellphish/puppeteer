import logging
l = logging.getLogger("puppeteer.manipulator")

import abc
import struct

from .errors import * #pylint: disable=wildcard-import

# pylint: disable=no-self-use,unused-argument
class Manipulator:
    __metaclass__ = abc.ABCMeta

    def __init__(self, endness='<', bits=32):
        '''
        This should connect to or spawn up the program in question.
        '''
        self.plt = { }
        self.endness = endness
        self.bits = bits
        self.bytes = bits/8

        self.rop_cleanups = { }

        if bits == 8:
            self.struct_fmt = endness + "B"
        elif bits == 16:
            self.struct_fmt = endness + "H"
        elif bits == 32:
            self.struct_fmt = endness + "I"
        elif bits == 64:
            self.struct_fmt = endness + "Q"
        else:
            raise Exception("Unsupported bitwidth!")

    #
    # Utility funcs
    #

    def pack(self, n):
        if type(n) in (int, long):
            return struct.pack(self.struct_fmt, n)

        if type(n) == str:
            return n

    #
    # Register disclosure
    #

    def read_register_safe(self, reg):
        '''
        This should read bytes from the register reg, and leave the program
        usable afterwards.
        '''
        raise CantDoItCaptainError("Please implement read_register_safe!")

    def read_register_unsafe(self, reg):
        '''
        This should read bytes from the register reg, and can leave the program
        unusable afterwards.
        '''
        return self.read_register_safe(self)

    #
    # Register overwrites
    #

    def write_register_safe(self, reg, content):
        '''
        This should write content to addr, and leave the program in a usable
        state (for other functions) afterwards.
        '''
        raise CantDoItCaptainError("Please implement read_register_safe!")

    def write_register_unsafe(self, reg, content):
        '''
        This should write content to addr, and can leave the program
        in an unusable state (i.e., crashed) afterwards.
        '''
        return self.write_register_safe(reg, content)



    #
    # Memory disclosure
    #

    def read_bytes_safe(self, addr, length):
        '''
        This should read length bytes from addr, and leave the program
        in a usable state (for other functions) afterwards.
        '''
        s = ""
        for i in range(length):
            s += self.read_byte_safe(addr+i)
        return s

    def read_byte_safe(self, addr):
        '''
        This should read one byte from addr, and leave the program
        in a usable state (for other functions) afterwards.
        '''
        raise CantDoItCaptainError("Please implement read_byte_safe!")

    def read_bytes_unsafe(self, addr, length):
        '''
        This should read length bytes from addr, and can leave the program
        in an unusable state (i.e., crashed) afterwards.
        '''
        return self.write_bytes_safe(addr, length)

    def read_byte_unsafe(self, addr):
        '''
        This should read one byte from addr, and can leave the program
        in an unusable state (i.e., crashed) afterwards.
        '''
        raise CantDoItCaptainError("Please implement read_byte_unsafe!")

    #
    # Overwrites
    #

    def write_bytes_safe(self, addr, content):
        '''
        This should write content to addr, and leave the program in a usable
        state (for other functions) afterwards.
        '''
        for i,c in enumerate(content):
            self.write_byte_safe(addr+i, c)

    def write_array_safe(self, addr, content):
        '''
        Writes an array of bitwidth-sized bytes. Should be safe. If an entry
        is None, it skips it.
        '''
        for i,c in enumerate(content):
            if c is not None:
                self.write_bytes_safe(addr+(i*bytes), c)

    def write_byte_safe(self, addr, content):
        '''
        This should write one byte to addr, and leave the program
        in a usable state (for other functions) afterwards.
        '''
        raise CantDoItCaptainError("Please implement write_byte_safe!")

    def write_bytes_unsafe(self, addr, content):
        '''
        This should write content to addr, and can leave the program
        in an unusable state (i.e., crashed) afterwards.
        '''
        return self.write_bytes_safe(addr, content)

    def write_byte_unsafe(self, addr, content):
        '''
        This should write content (which must be one byte) to addr, and can
        leave the program in an unusable state (i.e., crashed) afterwards.
        '''
        raise CantDoItCaptainError("Please implement write_byte_unsafe!")

    def write_array_unsafe(self, addr, content):
        '''
        Writes an array of bitwidth-sized bytes. Can be unsafe. If an entry
        is None, it skips it.
        '''
        return self.write_array_safe(addr, content)

    #
    # More complex stuff
    #

    def redirect_library_function(self, name, target):
        '''
        Redirects a PLT entry to jump to target.
        '''
        self.write_bytes_safe(self.plt[name], self.pack(target))

    #
    # ROP stuff
    #

    def rop_site_array(self, call_target, ret_target, args, cleanup=True):
        s = [ ]

        # this is what we're calling
        s.append(self.pack(call_target))

        # this is where we'll return to immediately
        if cleanup:
            s.append(self.pack(self.rop_cleanups[len(args)]))
        else:
            s.append(self.pack(ret_target))

        # our arguments
        for a in args:
            if a is not None:
                s.append(self.pack(a))
            else:
                s.append(None)

        # if we're cleaning up, *now* we return to the ret target
        if cleanup and ret_target is not None:
            s.append(self.pack(ret_target))

        return s

    def rop_site_bytes(self, *args, **kwargs):
        s = ""
        for w in self.rop_site_array(*args, **kwargs):
            if w is not None:
                s += w
            else:
                s += 'A' * self.bytes
        return s
