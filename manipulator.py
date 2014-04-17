import logging
l = logging.getLogger("puppeteer.manipulator")

import abc
import struct
import string # pylint: disable=W0402
import itertools
import functools

from .errors import NotLeetEnough
from .formatter import FmtStr
from .architectures import x86
from .rop import ROPChain, ROPGadget

def _safe_unsafe(f):
    '''
    If safe is None, try safe first, then unsafe.
    '''

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if 'safe' not in kwargs or kwargs['safe'] is None:
            try:
                kwargs['safe'] = True
                return f(*args, **kwargs)
            except NotLeetEnough:
                kwargs['safe'] = False
                return f(*args, **kwargs)
        else:
            return f(*args, **kwargs)

    return wrapper


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

        self.got_base = 0
        self.got_size = 0
        self.got_names = [ ]

    #
    # Utility funcs
    #

    def fix_endness_strided(self, s):
        '''
        Goes through the string, in chunks of the bitwidth of the architecture,
        and fixes endness.
        '''
        if self.arch.endness == '>':
            return s

        return "".join([ s[i:i+self.arch.bytes][::-1] for i in range(0, len(s), self.arch.bytes) ])



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
            r = vulns + unsafe_vulns
        elif safe:
            r = vulns
        elif not safe:
            r = unsafe_vulns

        if len(r) == 0:
            raise NotLeetEnough("Couldn't find a %s vuln with safe=%s (others might have been tried and failed previously)" % (t, safe))
        return r

    def _do_vuln(self, vuln_type, args, kwargs, safe=None):
        funcs = self._get_vulns(vuln_type, safe)

        for f in funcs:
            try:
                l.debug("Trying function %s", f.func_name)
                return f(*args, **kwargs)
            except NotLeetEnough:
                l.debug("... failed!")

        l.debug("Couldn't find an appropriate vuln :-(")
        raise NotLeetEnough("No %s%s functions available!" % (('safe ' if safe is True else ('unsafe ' if self is False else '')), vuln_type))

    #
    # Actions!
    #

    @_safe_unsafe
    def do_memory_read(self, addr, length, safe=None):
        ''' Finds and executes an vuln that does a memory read. '''

        # first, try to do it directly
        try:
            funcs = self._get_vulns('memory_read', safe)

            for f in funcs:
                l.debug("Trying a direct memory read with %s", f.__name__)
                max_size = f.puppeteer_flags['max_size']

                r = ""
                while len(r) < length:
                    toread = min(length, max_size)
                    l.debug("... reading %d bytes", toread)
                    r += f(addr + len(r), toread)
                return r
        except NotLeetEnough:
            l.debug("... l4m3!")

        # now do the printf path
        return self.do_printf_read(addr, length, safe=safe)

    @_safe_unsafe
    def do_register_read(self, reg, safe=None):
        ''' Finds and executes an vuln that does a register read. '''
        return self._do_vuln('register_read', (reg,), { }, safe=safe)

    @_safe_unsafe
    def do_memory_write(self, addr, content, safe=None):
        ''' Finds and executes an vuln that does a memory write. '''

        l.debug("First trying a direct memory write.")
        try:
            return self._do_vuln('memory_write', (addr, content), { }, safe=True)
        except NotLeetEnough:
            l.debug("... just can't do it, captain!")

        l.debug("Now trying a naive printf write.")
        return self.do_printf_write((addr, content), safe=safe)

    @_safe_unsafe
    def do_register_write(self, reg, content, safe=None):
        ''' Finds and executes an vuln that does a register write. '''
        return self._do_vuln('register_write', (reg, content), { }, safe=safe)

    @_safe_unsafe
    def do_printf(self, fmt, safe=None):
        '''
        Finds and executes an vuln that does a memory read.

        @param fmt: the format string!
        @param safe: safety!
        '''
        funcs = self._get_vulns('printf', safe)

        for f in funcs:
            try:
                l.debug("Trying function %s", f.func_name)
                if isinstance(fmt, FmtStr):
                    fmt.set_flags(**f.puppeteer_flags['fmt_flags'])
                    result = f(fmt.build())
                    if len(result) < fmt.before_absolute_reads:
                        return ""
                    else:
                        result = result[fmt.before_absolute_reads:].rstrip(fmt.pad_char)
                    return result
                elif isinstance(fmt, str):
                    return f(fmt)
                else:
                    raise Exception("Unrecognized format string type. Please provide FmtStr or str")
            except NotLeetEnough:
                l.debug("... failed!")

        l.debug("Couldn't find an appropriate vuln :-(")
        raise NotLeetEnough("No %s%s functions available!" % (('safe ' if safe is True else ('unsafe ' if self is False else '')), 'printf'))

    @_safe_unsafe
    def do_printf_read(self, addr, length, max_failures=10, safe=None):
        '''
        Do a printf-based memory read.

        @param addr: the address
        @param length: the number of bytes to read
        @param default_char: if something can't be read (for example, because
                             of bad chars in the format string), replace it
                             with this
        @param max_failures: the maximum number of consecutive failures before
                             giving up.
        @param safe: safety
        '''
        l.debug("Reading %d bytes from 0x%x using printf", length, addr)

        max_failures = length if max_failures is None else length
        failures = 0

        content = ""
        while len(content) < length:
            cur_addr = addr + len(content)
            left_length = length - len(content)
            fmt = FmtStr(self.arch).absolute_read(cur_addr)

            try:
                new_content = self.do_printf(fmt, safe=safe)[:left_length]
            except NotLeetEnough:
                failures += 1
                content += '\00'
                continue

            content += new_content
            if len(new_content) == 0:
                l.debug("... potential null byte")
                content += '\x00'

            if failures > max_failures:
                raise NotLeetEnough("do_printf_read hit more than %d consecutive failures", max_failures)

        return content

    @_safe_unsafe
    def do_printf_write(self, writes, safe=None):
        '''
        Do a memory write using a printf vulnerability.

        @param writes: a tuple of (addr, bytes) tuples
        @param safe: whether it's ok for the program to stop functioning afterwards
        '''

        # this is an overwrite of a set of bytes. We don't care about the output.
        chunks = [ (writes[0]+i, j) for i,j in enumerate(writes[1]) ]
        fmt = FmtStr(self.arch).absolute_writes(chunks)
        return self.do_printf(fmt, safe=safe)

    @_safe_unsafe
    def do_relative_read(self, offset, length, reg=None, safe=None):
        try:
            reg = self.arch.sp_name if reg is None else reg
            return self.do_memory_read(self.do_register_read(reg) + offset, length)
        except NotLeetEnough:
            if reg != self.arch.sp_name:
                raise

            result = ""
            while len(result) < length:
                fmt = FmtStr(self.arch).relative_read(offset/self.arch.bytes, length/self.arch.bytes)
                result += self.do_printf(fmt, safe=safe)
            return self.fix_endness_strided(result.decode('hex'))

    #
    # More complex stuff
    #

    def read_got_entry(self, which, safe=None):
        if type(which) == str:
            which = self.got_names.index(which)
        return self.do_memory_read(self.got_base+which*self.arch.bytes, self.arch.bytes, safe=safe)

    def dump_got(self, safe=None):
        return self.do_memory_read(self.got_base, self.got_size*self.arch.bytes, safe=safe)

    def do_page_read(self, addr):
        base = addr - (addr % self.arch.page_size)
        return self.do_memory_read(base, self.arch.page_size)

    def redirect_library_function(self, name, target, safe=None):
        '''
        Redirects a PLT entry to jump to target.

        @params name: the name to redirect
        @params target: the address to redirect to
        '''
        self.do_memory_write(self.plt[name], self.pack(target), safe=safe)

    def read_stack(self, length):
        '''
        Read the stack, from the current stack pointer (or something close), to sp+length

        @params length: the number of bytes to read. More bytes might be attempted if we end up using
                        a printf
        @params safe: if True, only do a safe read, if False, only do an unsafe read, if None do either
        '''

        return self.do_relative_read(0, length, reg=self.arch.sp_name)

    def main_return_address(self, start_offset=1):
        '''
        Get the return address that main will return to. This is usually
        libc_start_main, in libc, which gets you the address of (and a pointer
        into) libc off of a relative read.
        '''

        # strategy:
        # 1. search for a return address to main
        # 2. look for main's return address (to __libc_start_main)
        # 3. awesome!

        l.debug("Looking for libc!")

        for i in itertools.count(start=start_offset):
            l.debug("... checking offset %d", i)
            v = self.unpack(self.do_relative_read(i*self.arch.bytes, self.arch.bytes))
            if v >= self.locations['main'] and v <= self.locations['#main_end']:
                l.debug("... found the return address to main (specifically, to 0x%x) at offset %d!", v, i)
                break

        i += 3 + self.info['main_stackframe_size'] / self.arch.bytes # pylint: disable=undefined-loop-variable
        l.debug("... the return address into __libc_start_main should be at offset %d", i)

        v = self.unpack(self.do_relative_read(i*self.arch.bytes, self.arch.bytes))
        return v

    def dump_pageset(self, addr):
        '''
        Dumps a page at the given address, along with any adjacent page that
        pointers are found to. The idea is to use this to dump libraries.
        '''
        addr -= addr % self.arch.page_size

        pages = { }
        queue = [ addr ]
        l.info("Dumping pages around 0x%x", addr)

        while len(queue) != 0:
            a = queue.pop()
            l.info("... dumping page 0x%x", a)
            pages[a] = self.do_memory_read(a, self.arch.page_size)

            # TODO: the following only works on, at best, static binaries
            # that we just don't have locally. It won't work for things
            # that use relative jumps (almost everything). For that,
            # we should really disassemble the dumped page...
            if self.pack(a - self.arch.page_size) in pages[a]:
                l.info("... 0x%x found!", a - self.arch.page_size)
                queue.append(a - self.arch.page_size)
            if self.pack(a + self.arch.page_size) in pages[a]:
                l.info("... 0x%x found!", a + self.arch.page_size)
                queue.append(a + self.arch.page_size)

        return pages

    #
    # Crazy UI
    #
    def memory_display(self, p, addr):
        perline = 24
        print ""
        print "# Displaying the page at 0x" + (self.arch.python_fmt % addr)
        print ""
        for i in range(0, len(p), perline):
            line = p[i:i+perline]
            count = 0
            for c in line:
                print c.encode('hex'),
                count += 1
                if count % 4 == 0:
                    print "",

            print '|',"".join([ (c if c in string.letters + string.digits + string.punctuation else '.') for c in line ])

        nums = sorted(tuple(set(struct.unpack(self.arch.endness + str(self.arch.page_size/self.arch.bytes) + self.arch.struct_char, p))))

        perline = 10
        print ""
        print "# Aligned integers in the page:"
        print ""
        for i in range(0, len(nums), perline):
            line = nums[i:i+perline]
            print " ".join([ self.arch.python_fmt % c for c in line ])

        nums = sorted(tuple(set([ i - i%self.arch.page_size for i in struct.unpack(self.arch.endness + str(self.arch.page_size/self.arch.bytes) + self.arch.struct_char, p) ])))

        perline = 10
        print ""
        print "# Possible pages to look at next:"
        print ""
        for i in range(0, len(nums), perline):
            line = nums[i:i+perline]
            print " ".join([ self.arch.python_fmt % c for c in line ])

    def memory_explorer(self):
        '''
        This launches an interactive memory explorer, using a memory read vuln.
        It should probably be moved somewhere else.
        '''
        print "###"
        print "### Super Memory Explorer 64"
        print "###"
        print ""
        sp = self.do_register_read('esp')
        print "SP:", hex(sp)

        a = 'asdf'
        addr = None

        while a != 'q':
            print ""
            print "# Please enter one of:"
            print "#"
            print "#    - sp (to go back to the stack)"
            print "#    - a hex address (to look at its page)"
            print "#    - q (to quit)"
            print "#    - '' or 'n'(to look at the next page)"
            print "#    - 'p' (to look at the previous page)"
            a = raw_input("> ")

            if a in ['sp']:
                addr = sp
            elif a in ['', 'n']:
                addr = addr + self.arch.page_size if addr is not None else sp
            elif a in ['p']:
                addr = addr - self.arch.page_size if addr is not None else sp
            else:
                try:
                    addr = int(a, 16)
                except ValueError:
                    continue

            addr -= addr % self.arch.page_size

            p = self.do_page_read(addr)
            self.memory_display(p, addr)

    #
    # ROP stuff
    #

    def rop(self, *args, **kwargs):
        '''
        This returns a new ROP chain that you can then add ROP craziness to.
        '''
        return ROPChain(arch=self.arch, *args, **kwargs)

    def gadget(self, *args, **kwargs):
        '''
        This returns a new ROPGadget (and takes the same args as ROPGadget).
        '''
        return ROPGadget(self.arch, *args, **kwargs)
