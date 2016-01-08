#! /usr/bin/env python
# -*- coding: utf-8 -*-

def int_to_binstr(a):
    """ Convert int number to binary string """
    size = len(hex(a)[2:]) * 4
    return (bin(a)[2:]).zfill(size)

def binstr_to_int(a):
    """ Convert binary string to int """
    return int(a, 2)

def binstr_to_hex(a):
    """ Convert binary string to hex """
    return hex(binstr_to_int(a))

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
        initial_lfsr = int_to_binstr(initial_lfsr)

        # We generate the first part of the nonce (16 bit length)
        nonce = self.prng(initial_lfsr, clock_tick)

        """ From paper "Dismantling Mifare Classic": Sinces nonces 
        are 32 bits long and the LFSR has a 16 bit state, 
        the first half of Nt determines the second half. """

        # Now we generate the second half based on the first part
        nonce += self.prng(nonce, clock_tick)

        # We convert it
        self.nonce = binstr_to_int(nonce)

        # Return nonce, it will be sent to the reader
        return self.nonce

    def update_cipher(self, input):
        """ After initialization of the nonce Nt, we can feed the 
        48-bit LFSR with the uid tag, the key sector and the nonce Nt. 
        After the initialization, the 48-bit LFSR, we will be 
        feed with suc(Nt). """

        # The feedback bits generated from g(x) are not taken in account

        if self.lfsr is None:
            """ We directly put the input in the lsfr
            Generally, at the beginning, the input correspond
            to the xoring of the uid, key and nonce Nt """
            self.lfsr = input
        else:
            """ We update the state of the lfsr by
            xoring the lfsr with the input """ 
            self.lfsr = self.lfsr ^ input

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

