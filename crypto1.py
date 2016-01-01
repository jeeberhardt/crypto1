#! /usr/bin/env python
# -*- coding: utf-8 -*-

def int_to_binstr(a):
    """
    Convert int number to binary string
    """
    size = len(hex(a)[2:]) * 4
    return (bin(a)[2:]).zfill(size)

def binstr_to_int(a):
    """
    Convert binary string to int
    """
    return int(a, 2)

def binstr_to_hex(a):
    """
    Convert binary string to hex
    """
    return hex(binstr_to_int(a))

class Crypto1:
    """ 
    Implementation of the crypto1 Mifare algorithm 
    """
    def __init__(self, key):
        """ 
        The LSFR is iniatlized with the key sector 
        after received the auth command from the reader
        """
        self.lfsr = key
        self.nonce = ""

    def xor_bytes(self, a, b):
        """ XOR function """
        assert a.bit_length() != b.bit_length(), "bit length are not equal"
        return hex(a ^ b)

    def prng(self, lfsr, tick_clock = 1):
        """
        Apply 16-bit LFSR. At least one bit must be different than 0.
        I am sure we can do better, but for simplicity and clarity we use string.
        """
        for _ in xrange(0, tick_clock, 16):

            output = ""

            for _ in xrange(16):
                bit = str(int(lfsr[0],2) ^ int(lfsr[10],2) ^ int(lfsr[12],2) \
                          ^ int(lfsr[13],2) ^ int(lfsr[15],2))

                # We insert the new bit at the beginning 
                lfsr = bit + lfsr
                # And we take the last bit that we add to the nonce
                output += lfsr[-1]
                # And we remove it
                lfsr = lfsr[0:-1]

        return output

    def initialize_nonce(self, initial_lfsr, tick_clock = 1):
        """ 
        Function to generate initial Nt nonce. The 16 bit LFSR is 
        iniatialized during the authentification protocol.
        The generating polynomial is x16 + x14 + x13 + x11 + 1.
        How LFSR works: https://www.youtube.com/watch?v=sKUhFpVxNWc
        """
        # Initialize 16-bit LFSR with a "random number"
        initial_lfsr = int_to_binstr(initial_lfsr)

        # We generate the first part of the nonce (16 bit length)
        nonce = self.prng(initial_lfsr, tick_clock)

        """
        From paper "Dismantling Mifare Classic": Sinces nonces 
        are 32 bits long and the LFSR has a 16 bit state, 
        the first half of Nt determines the second half.
        """

        # Now we generate the second half based on the first part
        nonce += self.prng(nonce, tick_clock)

        # We convert it
        self.nonce = binstr_to_int(nonce)

        # Return nonce, it will be sent to the reader
        return self.nonce

    def initialize_lfsr(self):
        """
        After initialization of the nonce Nt, we can feed the 
        48-bit LFSR with the uid tag, the key sector and 
        the nonce Nt
        """

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
initial_lfsr = 0x104A
tick_clock = 16*10

card = Tag(uid, key)
Nt = card.initialize_nonce(initial_lfsr, tick_clock)

print hex(Nt)
print card
