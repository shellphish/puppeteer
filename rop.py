from .errors import NoobError

class ROPChain(object):
    def __init__(self, arch, chain=None, length=None):
        self.arch = arch
        self.chain = chain if chain is not None else [ ]
        self.length = length

    def add(self, entry):
        if len(entry) != self.arch.bytes:
            raise NoobError("unaligned?")

        self.chain.append(entry)

    def __add__(self, entry):
        if isinstance(entry, ROPChain):
            return ROPChain(self.chain + entry.chain)
        else:
            r = ROPChain(self.chain)
            r.add(entry)
            return r

    def __iadd__(self, entry):
        if isinstance(entry, ROPChain):
            self.chain += entry.chain
        else:
            self.add(entry)

        return self

    def build(self):
        if self.length is not None and len(self.chain) != self.length:
            raise NoobError("size doesn't match!")

        return "".join(self.chain)
