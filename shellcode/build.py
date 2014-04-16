
import os
import tempfile
import subprocess

class SCBuilder(object):
    """
        Wrapper for building shellcode with GAS
        and getting raw bytes with objcopy
    """

    def __init__(self, arch, asmopts=None):
        self.arch = arch
        self.asmopts = [ ] if asmopts is None else asmopts

    # build the shellcode for the given arch and return
    # the raw bytes
    def build(self, sc):
        tmpf = tempfile.NamedTemporaryFile(delete=False)
        tmpf.write(sc)
        fname = tmpf.name
        tmpf.close()

        oname = fname + ".o"
        binname = fname + ".bin"
        assembler = self.arch.gas
        copier = self.arch.objcopy
        r = subprocess.call([assembler, "-o", "%s.o"%(oname)] + self.asmopts)
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
