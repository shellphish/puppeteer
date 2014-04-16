"""
    A Shellcode is made of up of ShellcodeModules
    There is "convention" between modules.
    Important values are returned in eax/rax,r0 (arm), r3 (ppc), $v0 (mips) 
    and are aslo read from eax if needed.
    For example: open() module will return the fd in eax and read() module
    will read from the eax register
"""

import os

class Shellcode(object):
    def __init__(self):
        pass
    def assemble(self):
        pass

class ShellcodeModule(object):
    def __init__(self, arch, port)
        pass

# Connect to ip, port
class ConnectModule(ShellcodeModule):
    def __init__(self, arch, ip, port):
        pass
# Bind top port
class BindModule(NetShellcodeModule):
    def __init__(self, arch, port):
        pass

# Find socket (getpeername())
class FindSockModule(ShellcodeModule):
    def __init__(self, arch, port):

# open(filename)
class OpenModule(ShellcodeModule):
    def __init__(self, arch, sockfd, filename, size):
        pass

# read(fd, size)
# by default fd is whatever is in eax
# by default where is the stack pointer
class ReadModule(ShellcodeModule):
    def __init__(self, arch, size, fd=None, where=None):
        pass

# write(fd, size)
# by default what is the stack pointer
class WriteModule(ShellcodeModule):
    def __init__(self, arch, size, fd, what=None):
        pass

# dup2(fdt, fdf)
class DupModule(ShellcodeModule):
    def __init__(self, arch, fdt, fdf):
        pass

# execve(exe, [exe], NULL)
class ExecveModule(ShellcodeModule):
    def __init__(self, arch, exe)
        pass

# execve("/bin/sh", ["/bin/sh", "-C", cmd], NULL)
class ShCModule(ShellcodeModule):
    def __init__(self, arch, cmd):
        pass
