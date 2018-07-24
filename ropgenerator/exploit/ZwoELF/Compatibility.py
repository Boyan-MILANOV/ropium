import struct


"""
	Python 2.7.3 issue:
	struct.unpack(fmt, buffer) does not work if buffer is a bytearray.
	(Works with Python 2.7.8.)

	This compatibility workaround was written when python 2.7.3 was current in
	Debian stable.
"""
try:
	struct.unpack('<H', bytearray('AB'))
except:
	__old_struct_unpack = struct.unpack

	def __struct_unpack_wrapper(fmt, buffer):
		if type(buffer) is bytearray:
			buffer = bytes(buffer)
		return __old_struct_unpack(fmt, buffer)

	struct.unpack = __struct_unpack_wrapper
