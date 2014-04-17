#!/usr/bin/env python

import logging
l = logging.getLogger("puppeteer.formatter")
l.setLevel(logging.DEBUG)

import struct

class FmtStr(object):
	def __init__(self, arch, word_offset=None, max_length=None, byte_offset=None, num_written=0, prefix="", pad_length=None, pad_round=None, pad_char='_'):
		self.arch = arch
		self.offset = word_offset * self.arch.bytes if byte_offset is None else byte_offset
		self.prefix = prefix
		self.pad_length = pad_length
		self.pad_round = pad_round
		self.pad_char = pad_char
		self.max_length = max_length

		self.absolute_reads = [ ]
		self.absolute_writes = [ ]
		self.relative_reads = [ ]
		self.pointed_writes = [ ]

		# in-progress building
		self._fmt = ""
		self._idx = 1
		self._printed = num_written
		self._undos = [ ]

	def absolute_write(self, addr, buff):
		self.absolute_writes.append((addr, buff))
		return self

	def absolute_read(self, addr):
		self.absolute_reads.append(addr)
		return self

	def relative_read(self, offset=1, count=1):
		self.relative_reads.append((offset, count))
		return self

	def pointed_write(self, offset, buff):
		self.pointed_writes.append((offset, buff))
		return self

	#
	# Internal functions below
	#

	def _pad_start(self):
		'''
		Pads the start of the format string to the proper offset.
		'''
		self._fmt = self.prefix
		self._fmt += self.pad_char * ((-(self.offset + len(self._fmt))) % self.arch.bytes)
		self._pad_to_offset()
		self._printed = len(self._fmt)

	def _pad_to_offset(self):
		topad = (-(len(self._fmt) + self.offset)) % self.arch.bytes
		self._fmt += self.pad_char * topad
		self._printed += topad

	def _pad_end(self):
		'''
		Pads the end of format string to the proper offset.
		'''
		if self.pad_round is not None:
			topad = -len(self._fmt) % self.pad_round
		elif self.pad_length is not None:
			topad = -len(self._fmt) % self.pad_length
		else:
			topad = 0

		self._fmt += self.pad_char * topad
		self._printed += topad

	def _next_offset(self):
		'''
		Returns the offset of the next word of the string.
		'''
		l.debug("... calculating offset (%d + %d)/%d", self.offset, len(self._fmt), self.arch.bytes)
		return (self.offset + len(self._fmt)) / self.arch.bytes + 1

	def _undo(self):
		self._fmt, self._idx = self._undos.pop()

	def _checkpoint(self):
		self._undos.append((self._fmt, self._idx))

	def _do_relative_read(self, offset=0):
		self._checkpoint()

		sized_x = "0%dx" % (self.arch.bytes*2)
		if offset == self._idx:
			self._fmt += "%%%s" % sized_x
			self._idx += 1
		else:
			self._fmt += '%' + str(offset) + '$' + sized_x

	def _do_relative_reads(self):
		for offset,count in self.relative_reads:
			for i in range(count):
				self._do_relative_read(offset + i)

	def _do_absolute_writes(self):
		self._checkpoint()

		self._pad_to_offset()
		addr_offset = self._next_offset()
		l.debug("... initial addr offset: %d", addr_offset)
		self._fmt += "".join(struct.pack(self.arch.struct_fmt, t) for t, _ in self.absolute_writes)
		self._printed += self.arch.bytes * len(self.absolute_writes)

		modifiers = { 1: "hh", 2: "h", 4: "", 8: "ll" }
		struct_fmts = { 1: "B", 2: "H", 4: "I", 8: "Q" }
		for n,(t,c) in enumerate(self.absolute_writes):
			l.debug("... adding write to 0x%x of size %d", t, len(c))
			v = struct.unpack(self.arch.endness + struct_fmts[len(c)], c)[0]
			next_length = (v - self._printed) % (256 ** len(c))
	
			# For 4 and less characters, printing directly is more efficient
			# For 5 to 8, the general method can't be used
			# Otherwise, use general method
			if next_length < 5:
				self._fmt += self.pad_char * next_length
			elif next_length < 8:
				self._fmt += "%{:d}hhx".format(next_length)
			else:
				self._fmt += "%{:d}x".format(next_length)
			self._printed += next_length
	
			self._fmt += "%{:d}${:s}n".format(addr_offset + n, modifiers[len(c)])
	
	def _do_absolute_reads(self):
		self._checkpoint()

		self._pad_to_offset()
		addr_offset = self._next_offset()
		self._fmt += "".join(struct.pack(self.arch.struct_fmt, t) for t in self.absolute_reads)
		self._printed += self.arch.bytes * len(self.absolute_reads)

		for n in range(len(self.absolute_reads)):
			self._fmt += "%{:d}$s".format(addr_offset + n)
	
	def build(self):
		l.debug("Starting format string build...")
		self._pad_start()

		# carry out the actions. Absolute reads are last because we can't predict their output.
		self._do_relative_reads()
		self._do_absolute_writes()
		self._do_absolute_reads()

		while self.max_length is not None and len(self._fmt) > self.max_length:
			self._undo()
		self._pad_end()

		l.debug("... created format strng |%s| of length %s.", repr(self._fmt), len(self._fmt))
		return self._fmt
