#! /usr/bin/env python
# -*- coding: utf-8 -*-

def int_to_bitstr(a):
    """ Convert int number to binary string """
    size = len(hex(a)[2:]) * 4
    return (bin(a)[2:]).zfill(size)

def bitstr_to_int(a):
    """ Convert binary string to int """
    return int(a, 2)

def bitstr_to_hex(a):
    """ Convert binary string to hex """
    return hex(bitstr_to_int(a))

def int_to_hex(a):
    """ Convert int to hex """
    return hex(a)

class Crypto1:
    """ Implementation of the crypto1 Mifare algorithm """
    def __init__(self):
        """ The LSFR is iniatlized with the key sector 
        after received the auth command from the reader """
        self.lfsr = None
        self.nonce = None

    def prng(self, lfsr, clock_tick = 1):
        """ Apply 16-bit LFSR. At least one bit must be different than 0.
        I am sure we can do better, but for simplicity and clarity we use string. """
        for _ in xrange(0, clock_tick, 16):

            output = ""

            for _ in xrange(16):
                bit = str(int(lfsr[0],2) ^ int(lfsr[10],2) ^ int(lfsr[12],2) 
                          ^ int(lfsr[13],2) ^ int(lfsr[15],2))

                # We insert the new bit at the beginning 
                lfsr = bit + lfsr
                # And we take the last bit that we add to the nonce
                output += lfsr[-1]
                # And we remove it
                lfsr = lfsr[0:-1]

        return output

    def generate_nonce(self, initial_lfsr, clock_tick = 1):
        """ Function to generate initial Nt nonce. The 16 bit LFSR is 
        iniatialized during the authentification protocol.
        The generating polynomial is x16 + x14 + x13 + x11 + 1.
        How LFSR works: https://www.youtube.com/watch?v=sKUhFpVxNWc """
        # Initialize 16-bit LFSR with a "random number"
        initial_lfsr = int_to_bitstr(initial_lfsr)

        # We generate the first part of the nonce (16 bit length)
        nonce = self.prng(initial_lfsr, clock_tick)

        """ From paper "Dismantling Mifare Classic": Sinces nonces 
        are 32 bits long and the LFSR has a 16 bit state, 
        the first half of Nt determines the second half. """

        # Now we generate the second half based on the first part
        nonce += self.prng(nonce, clock_tick)

        # We convert it
        self.nonce = bitstr_to_int(nonce)

        # Return nonce, it will be sent to the reader
        return self.nonce

    def update_cipher(self, input):
        """ After initialization of the nonce Nt, we can feed the 
        48-bit LFSR with the uid tag, the key sector and the nonce Nt. 
        After the initialization, the 48-bit LFSR, we will be 
        feed with suc(Nt). """

        if self.lfsr is None:
            """ We directly put the input in the lsfr
            Generally, at the beginning, the input correspond
            to the xoring of the uid, key and nonce Nt """
            self.lfsr = input
        else:
            """ We update the state of the lfsr by
            xoring the lfsr with the input. For the moment,
            the feedback bits generated from g(x) are 
            not taken in account. But it should be at the 
            initialization step only ... """ 
            self.lfsr = self.lfsr ^ input

    def fa(self, a, b, c, d):
        """ Apply filter function A.
        f_a = ((a or b) xor (a and d)) xor (c and ((a xor b) or d)) """
        return ((a | b) ^ (a & d) ^ (c & (a ^ b) | d))

    def fb(self, a, b, c, d):
        """ Apply filter function B
        f_b = ((a and b) or c) xor (a xor b) and (c or d) """
        return ((a & b) | c) ^ (a ^ b) & (c | d)

    def fc(self, a, b, c, d, e):
        """ Apply filter function C
        f_c = (a or ((b or e) and (d xor e))) xor ((a xor 
        (b and d)) and ((c xor d) and (a and e))) """
        return (a | ((b | e) & (d ^ e))) ^ ((a ^ (b & d)) & ((c ^ d) & (a & e)))

    def cipher_feedback(self):
        """ Apply the feedback function on the cipher. The
        position 0,5,9,10,12,14,15,17,19,24,25,27,29,35
        39,41,42,43 are xored together. The content is shifted
        to the left by one position. The MSB (left) is removed
        and the new bit is added on the LSB side (right). """

    def generate_keystream(self):
        """ In order to generate the keystream the filter 
        functions are applied on the lfsr state """

class Tag(Crypto1):
    """ Create a Mifare tag with only one sector """
    def __init__(self, uid, keyA):
        """ A tag has an uid, a key and the crypto1"""
        self.uid = uid
        self.keyA = keyA
        Crypto1.__init__(self)

    def __str__(self):
        """ Informations about the tag """
        return "UID {0}, Key {1}".format(hex(self.uid), hex(self.keyA))

uid = 0xc2a82df4
key = 0xa0b1c2d3f4
initial_lfsr = 0x104A #0001000001001010
clock_tick = 16

# Create a tag
card = Tag(uid, key)
print card

# Generate nonce Nt
Nt = card.generate_nonce(initial_lfsr, clock_tick)
print "Nt {0}".format(hex(Nt))

""" Now the tag send the nonce Nt to the reader, it will be use 
to feed its cipher, plus the uid and the key sector, like 
the tag did with its own. The 48-bit LFSR will be in the 
same state for both, the tag and the reader. Like that, they
can communicate with each other correctly. The Nonce Nt
will be send in the reverse order, the least significant 
bit first (LSB)(on the left) """

# Synchronize the 48-bit LFSR with uid, key and Nonce Nt
print "LFSR state {0}".format(card.lfsr)
card.update_cipher(uid ^ key ^ Nt)
print "LFSR state {0}".format(int_to_hex(card.lfsr))

