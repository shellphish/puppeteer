#!/usr/bin/env python

import logging
l = logging.getLogger("puppeteer.formatter")
#l.setLevel(logging.DEBUG)

import struct

from .errors import NotLeetEnough

class FmtStr(object):
	def __init__(self, arch, **kwargs):
		self.arch = arch
		self._absolute_reads = [ ]
		self._absolute_writes = [ ]
		self._relative_reads = [ ]
		self._pointed_writes = [ ]

		# initialize stuff that will be set later
		self.offset = None
		self.prefix = None
		self.pad_length = None
		self.pad_round = None
		self.pad_char = None
		self.max_length = None
		self.forbidden = None
		self.num_written = None
		self._fmt = None
		self._idx = None
		self._printed = None
		self._undos = None
		self.before_absolute_reads = None

		# and set it
		if len(kwargs) > 0:
			self.set_flags(**kwargs)
			self._clear_string()

	def set_flags(self, word_offset=None, max_length=None, byte_offset=None, num_written=None, prefix=None, pad_length=None, pad_round=None, pad_char=None, forbidden=None):
		self.offset = word_offset * self.arch.bytes if byte_offset is None else byte_offset
		self.prefix = "" if prefix is None else prefix
		self.pad_length = max_length if pad_length is None else pad_length
		self.pad_round = pad_round
		self.pad_char = "_" if pad_char is None else pad_char
		self.max_length = max_length
		self.forbidden = set() if forbidden is None else forbidden
		self.num_written = num_written

	def _clear_string(self):
		# in-progress building
		self._fmt = ""
		self._idx = 1
		self._printed = 0 if self.num_written is None else self.num_written
		self._undos = [ ]
		self.before_absolute_reads = 0

	def absolute_write(self, addr, buff):
		l.debug("Format string adding absolute write of %s to 0x%x", repr(buff), addr)
		self._absolute_writes.append((addr, buff))
		return self
	def absolute_writes(self, writes):
		for addr, buff in writes:
			self.absolute_write(addr, buff)
		return self

	def absolute_read(self, addr):
		l.debug("Format string adding absolute read of 0x%x", addr)
		self._absolute_reads.append(addr)
		return self
	def absolute_reads(self, reads):
		for addr in reads:
			self.absolute_read(addr)
		return self

	def relative_read(self, offset=None, count=1):
		l.debug("Format string adding relative read of %d words from offset %d", count, self._idx if offset is None else offset)
		self._relative_reads.append((offset, count))
		return self
	def relative_reads(self, reads):
		for offset, count in reads:
			self.relative_read(offset, count)
		return self

	def pointed_write(self, offset, buff):
		l.debug("Format string adding pointed write of %s through offset", repr(buff), offset)
		self._pointed_writes.append((offset, buff))
		return self
	def relative_writes(self, writes):
		for offset, buff in writes:
			self.pointed_write(offset, buff)
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
			topad = self.pad_length - len(self._fmt)
		else:
			topad = 0

		topad = max(topad, 0)
		self._fmt += self.pad_char * topad
		self._printed += topad

	def _next_offset(self):
		'''
		Returns the offset of the next word of the string. Assumes the string
		is properly padded.
		'''
		l.debug("... calculating offset (%d + %d)/%d", self.offset, len(self._fmt), self.arch.bytes)
		return (self.offset + len(self._fmt)) / self.arch.bytes # why not +1 here?

	def _undo(self):
		self._fmt, self._idx = self._undos.pop()

	def _checkpoint(self):
		self._undos.append((self._fmt, self._idx))

	def _do_relative_read(self, offset):
		self._checkpoint()
		offset = self._idx if offset is None else offset

		sized_x = "0%dx" % (self.arch.bytes*2)
		if offset == self._idx:
			self._fmt += "%%%s" % sized_x
			self._idx += 1
		else:
			self._fmt += '%' + str(offset) + '$' + sized_x

	def _do_relative_reads(self):
		for offset,count in self._relative_reads:
			for i in range(count):
				self._do_relative_read(offset + i)

	def _do_absolute_writes(self):
		self._checkpoint()

		self._pad_to_offset()
		addr_offset = self._next_offset()
		l.debug("... initial addr offset: %d", addr_offset)
		self._fmt += "".join(struct.pack(self.arch.struct_fmt, t) for t, _ in self._absolute_writes)
		self._printed += self.arch.bytes * len(self._absolute_writes)

		modifiers = { 1: "hh", 2: "h", 4: "", 8: "ll" }
		struct_fmts = { 1: "B", 2: "H", 4: "I", 8: "Q" }
		for n,(t,c) in enumerate(self._absolute_writes):
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
		self._fmt += "".join(struct.pack(self.arch.struct_fmt, t) for t in self._absolute_reads)
		self._printed += self.arch.bytes * len(self._absolute_reads)
		self.before_absolute_reads += self.arch.bytes * len(self._absolute_reads)

		for n in range(len(self._absolute_reads)):
			self._fmt += "%{:d}$s".format(addr_offset + n)
	
	def build(self, flags=None):
		l.debug("Starting format string build...")
		if flags is not None:
			self.set_flags(**flags)

		self._clear_string()
		self._pad_start()

		# carry out the actions. Absolute reads are last because we can't predict their output.
		if len(self._relative_reads) > 0:
			self._do_relative_reads()
		if len(self._absolute_writes) > 0:
			self._do_absolute_writes()
		if len(self._absolute_reads) > 0:
			self.before_absolute_reads = self._printed
			self._do_absolute_reads()

		#while self.max_length is not None and len(self._fmt) > self.max_length:
		#	self._undo()

		self._pad_end()

		for f in self.forbidden:
			if f in self._fmt:
				l.warning("Forbidden characters in format string!")
				raise NotLeetEnough("Forbidden characters in format string.")

		if self.max_length and len(self._fmt) > self.max_length:
			l.warning("Format string too long (%d/%d)!", len(self._fmt), self.max_length)
			raise NotLeetEnough("Format string too long (%d/%d)!" % (len(self._fmt), self.max_length))

		l.debug("... created format strng |%s| of length %s.", repr(self._fmt), len(self._fmt))
		return self._fmt
