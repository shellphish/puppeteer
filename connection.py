import socket
import select
import subprocess
import re

import logging
l = logging.getLogger('puppeteer.connection')
#l.setLevel(logging.DEBUG)

from .errors import ConnectionFail

def rw_alias(f):
    '''
    Makes an alias for read/recv and write/send.
    '''
    print "CLASS:",f.im_class
    return f

class Connection(object):
    '''
    A connection handler for puppeteer. Basically a wrapper around sockets or
    files.

    Will handle all sorts of intelligent stuff like timeouts and crap.
    '''
    def __init__(self, host=None, port=None, exe=None, args=(), s=None, fd=None):
        self.host = host
        self.port = port
        self.exe_args = [ exe ] + list(args)

        self.s = s
        self.p = fd
        self.connected = None if s is None and fd is None else True

    def copy(self):
        return Connection(host=self.host, port=self.port, exe=self.exe_args[0], args=self.exe_args[1:])

    def connect(self):
        '''
        Connect!
        '''
        if self.host is not None and self.port is not None:
            self.s = socket.create_connection((self.host, self.port))
        elif self.exe_args[0] is not None:
            self.p = subprocess.Popen(self.exe_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        else:
            raise Exception("How are we supposed to connect, man?")

        l.info("Connected!")
        self.connected = True
        return self

    def close(self):
        if self.s:
            self.s.close()
        elif self.p:
            self.p.close()

    def send(self, msg):
        '''
        Send the message.
        '''
        l.debug("Sending: %r", msg)

        try:
            if self.s is not None:
                return self.s.sendall(msg)
            elif self.p is not None:
                return self.p.stdin.write(msg)
        except socket.error as e:
            raise ConnectionFail(str(e))

    def recv(self, n, timeout=None, quash=False):
        '''
        Receive up to n bytes.
        '''
        #l.debug("recv(%d, timeout=%s)", n, timeout)
        slist = [ self.s if self.s is not None else self.p.stdout ]
        if timeout is not None:
            (rlist, _, _) = select.select(slist, [], [], timeout)
        else:
            (rlist, _, _) = select.select(slist, [], [])

        l.debug("recv with size %d and timeout %s", n, timeout)

        #print rlist, wlist, xlist
        if rlist == []:
            l.debug("RECV TIMEOUT")
            if not quash:
                raise ConnectionFail("very timeout")
            else:
                return ""
        try:
            readsock = rlist[0]
            if type(readsock) == socket.socket:
                r = readsock.recv(n)
            if type(readsock) == file:
                r = readsock.read(n)

            l.debug("read: %r",r)
        except socket.error:
            r = ""

        if len(r) == 0 and n != 0:
            raise ConnectionFail("Received nothing. Much sad.")

        #l.debug("Got: %r", r)
        return r

    def read(self, n=None, timeout=None, quash=False):
        '''
        Read exactly n bytes, or all that's available if n is None.
        '''
        if n is None:
            self.read_all(timeout=timeout)

        result = ""
        while len(result) < n:
            tmp = self.recv(n - len(result), timeout=timeout, quash=quash)
            if tmp == "" and timeout is not None:
                break
            result += tmp

        return result

    # read until the given string
    def read_until(self, c=None, regex=None, max_chars=None, timeout=None):
        '''
        Read until the given string, or matching the given regex.
        '''
        if c is None and regex is None:
            # they cannot both be None
            raise Exception('You must specify at least one argument')
        if c is not None and regex is not None:
            raise Exception('You cannot specify both c and regex.')

        if c is not None:
            l.debug("Reading until: %r", c)
        else:
            l.debug("Reading until: %s", regex)

        buf = ""
        tmp = None
        while max_chars is None or len(buf) < max_chars:
            l.debug("... so far: %s", buf)
            if c is not None and buf.endswith(c):
                break
            elif regex is not None and re.search(regex, buf):
                break

            tmp = self.recv(1, timeout=timeout)
            if tmp == "":
                break
            buf += tmp
        l.debug("... read: %r", buf)
        return buf

    def read_all(self, timeout=None, stepsize=8192):
        '''
        Read as long as there is more stuff and the timeout is not expired.
        '''
        buff = ""

        while True:
            try:
                s = self.recv(stepsize, timeout=timeout)
            except ConnectionFail:
                break

            if len(s) == 0:
                break
            buff += s

        return buff

    def shutdown(self, what):
        if self.s is not None:
            self.s.shutdown(what)
        elif self.p is not None:
            if what == socket.SHUT_WR:
                self.p.stdin.close()
            if what == socket.SHUT_RD:
                self.p.stdout.close()
