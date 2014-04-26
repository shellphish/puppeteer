# Common flags:
#
#   type: the type of the vuln
#   priority: determines which vulns to try first

# Memory write/read flags:
#
#   relative_to: what a relative read/write/etc is relative to (i.e., 'esp').
#                If None, assumed to be absolute.
#   max_size: maximum size of the write or read

# Printf flags:
#
#   blind: the printf gets no output
#   max_output_size: the maximum output size of the printf
#   word_offset: the offset (in words) to the format string
#   byte_offset: the offset (in bytes) to the format string
#   max_length: the maximum length of the format string
#   num_written: the number of bytes already printed (i.e., if the injection is
#                into the middle of a format string
#   prefix: the prefix to put into the format string
#   pad_length: the length to pad the format string to
#   pad_round: round the length of the format string to the closest N
#   pad_char: the character to pad the format string with (default: '_')
#   forbidden: a sequence of strings forbidden to be in the format string

import functools
import logging
l = logging.getLogger("puppeteer.vuln_decorators")

def exploit_runner(f, flags):
    @functools.wraps(f)
    def runner(self, *args, **kwargs):
        if self._implemented_connect() and not self._is_connected():
            l.debug("Connecting!")
            self.connect()
        try:
            return f(self, *args, **kwargs)
        except FUBARed:
            if self._implemented_connect():
                self.connected = False
            unleet("FUBARed!")

    setattr(runner, 'puppeteer_flags', flags)
    return runner

def make_flags(**kwargs):
    return kwargs

#
# The vulns
#

def memory_read(max_size=None,
                priority=None):
    flags = make_flags(type='memory_read', max_size=max_size,
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

def memory_write(max_size=None,
                 priority=None):
    flags = make_flags(type='memory_read', max_size=max_size,
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

def register_read(
    priority=None):
    flags = make_flags(type='memory_read',
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

def register_write(
    priority=None):
    flags = make_flags(type='memory_read',
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

def printf(blind=False, max_output_size=None, word_offset=None, max_length=None, byte_offset=None, num_written=None, prefix=None, pad_length=None, pad_round=None, pad_char=None, forbidden=None,
           priority=None):
    fmt_flags = make_flags(word_offset=word_offset, max_length=max_length, byte_offset=byte_offset, num_written=num_written, prefix=prefix, pad_length=pad_length, pad_round=pad_round, pad_char=pad_char, forbidden=forbidden)
    flags = make_flags(type='printf', blind=blind, max_output_size=max_output_size, fmt_flags=fmt_flags,
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

def stack_overflow(ip_distance=None, canary_distance=None, bp_distance=None,
                   priority=None):
    flags = make_flags(type='stack_overflow', canary_distance=canary_distance, ip_distance=ip_distance, bp_distance=bp_distance,
                    priority=priority)
    return lambda f: exploit_runner(f, flags)

#
# Some other decorators
#
def crashes(f):
    @functools.wraps(f)
    def crasher(self, *args, **kwargs):
        r = f(self, *args, **kwargs)
        self._crash()
        return r

    #if hasattr(f, 'puppeteer_flags'): setattr(crasher, 'puppeteer_flags', f.puppeteer_flags)
    return crasher

def disconnects(f):
    @functools.wraps(f)
    def disconnector(self, *args, **kwargs):
        r = f(self, *args, **kwargs)
        self._disconnect()
        return r
    #if hasattr(f, 'puppeteer_flags'): setattr(disconnector, 'puppeteer_flags', f.puppeteer_flags)
    return disconnector

from .errors import FUBARed
from .utils import unleet
