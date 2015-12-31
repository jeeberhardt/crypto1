#! /usr/bin/env python
# -*- coding: utf-8 -*-

class Crypto1:
	""" 
	Implementation of the crypto1 Mifare algorithm 
	"""
	def __init__(self, key):
		""" The LSFR is iniatlized with the key sector 
		after received the auth command from the reader
		"""
		self.lfsr = key

	def xor_bytes(self, a, b):
		""" XOR function """
		assert a.bit_length() != b.bit_length(), "bit length are not equal"
		return hex(a ^ b)

class Tag(Crypto1):
	""" 
	Create a Mifare tag with only one sector 
	"""
	def __init__(self, uid, keyA):
		""" A tag has an uid, a key and the crypto1"""
		self.uid = uid
		self.keyA = keyA
		Crypto1.__init__(self, keyA)

	def __str__(self):
		""" Informations about the tag """
		return "UID {0}, Key {1}".format(hex(self.uid), hex(self.keyA))

uid = 0xc2a82df4
key = 0xa0b1c2d3f4

card = Tag(uid, key)
print card
