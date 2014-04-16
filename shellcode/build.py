
import os
import tempfile
import subprocess

class ARMTools:
    gas = "arm-as"
    objcopy = "arm-objcopy"

class x86Tools:
    gas = "x86-as"
    objcopy = "x86-objcopy"

class x86_64Tools:
    gas = "x86_64-as"
    objcopy = "x86_64-objcopy"

class MIPSTools:
    gas = "mips-as"
    objcopy = "mips-objcopy"

class PPCTools:
    gas = "ppc-as"
    objcopy = "ppc-objcopy"

class ARCH:
    """
        An enum for types of architectures
    """
    ARM = ARMTools
    x86 = x86Tools
    x86_64 = x86_64Tools
    MIPS = MIPSTools
    PPC = PPCTools

class SCBuilder(object):
    """
        Wrapper for building shellcode with GAS
        and getting raw bytes with objcopy
    """

    def __init__(self, arch, asmopts=[]):
        self.arch = arch
        self.asmopts = []

    # build the shellcode for the given arch and return
    # the raw bytes
    def build(self, sc):
        tmpf = tempfile.NamedTemporaryFile(delete=False)
        tmpf.write(sc)
        fname = tmpf.name
        tmpf.close()

        oname = fname + ".o"
        binname = fname + ".bin"
        assembler = arch.gas
        copier = arch.objcopy
        r = subprocess.call([assembler, "-o", "%s.o"%(oname)] + asmopts)
        if r:
            raise Exception("Could not assemble shellcode")
        
        r = subprocess.call([copier, "-O", "binary", oname, binname])
        if r:
            raise Exception("Could not get raw bytes of shellcode")

        rawbytes = open(binname, "r").read()
        os.unlink(fname)
        os.unlink(oname)
        os.unlink(binname)
        return rawbytes
