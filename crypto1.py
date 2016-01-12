#! /usr/bin/env python
# -*- coding: utf-8 -*-

def int_to_bitstr(a, size = None):
    """ Convert int number to binary string """
    if size is None:
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
    def __init__(self, key, initial_prng):
        """ The LSFR is iniatlized with the key sector 
        after received the auth command from the reader """
        self.cipher = key
        self.prng = initial_prng
        self.nonce = None

    def prng_feedback(self, lfsr):
        """ Apply the feedback function of the pseudo-random
         generator is defined by x0 xor x2 xor x3 xor x5. """
        return str(int(lfsr[0],2) ^ int(lfsr[2],2) ^ int(lfsr[3],2) ^ int(lfsr[5],2))

    def suc_nonce(self):
        """ Function to generate the successor nonce based 
        on a 16 bit LFSR. Since the nonce is 32 bit and the
        LFSR is only 16 bit, the first half of the nonce 
        will define the second half. Every clock tick the 
        LFSR shifts to the left. A new feedback bit is added 
        on the right and the bit on the left is discarded. 
        How LFSR works: https://www.youtube.com/watch?v=sKUhFpVxNWc """

        # if nonce already exists, we generate the suc(Nt)
        if self.nonce:

            """ We convert the nonce and the prng in bit 
            in order to work on them. """
            prng = int_to_bitstr(self.prng, 16)
            nonce = int_to_bitstr(self.nonce, 32)

            """ Generate the feedback bit based on the nonce's 
            second half, because the last 16 bits of the nonce is
            identical to the 16 bits prng state. """
            fbit = self.prng_feedback(prng)

            # The left bit is discarded and the feedback bit is added
            nonce = nonce[1:] + fbit
            # The same for the prng state
            prng = prng[1:] + fbit
        else:
            """ If the nonce doesn't exist. First we will initiate
            the nonce with the prng. This will be the first part. """
            nonce = int_to_bitstr(self.prng, 16)

            """ Then we generate the second by taking only the
            last 16 bits until we have 32 bits in total. """
            for i in range(16):
                nonce += self.prng_feedback(nonce[i:i+16])

            """ The new state of the prng will be the last 16 bits
            of the nonce, because we discarded 16 bits during the
            feedback loop. The initial nonce has 32 bits now. """
            prng = nonce[16:]

        self.prng = bitstr_to_int(prng)
        self.nonce = bitstr_to_int(nonce)

        # Return nonce, it will be sent to the reader
        return self.nonce

    def update_cipher(self, input):
        """ After initialization of the nonce Nt, we can feed the 
        48-bit LFSR with the uid tag, the key sector and the nonce Nt. 
        After the initialization, the 48-bit LFSR, we will be 
        feed with suc(Nt). """

        if self.cipher is None:
            """ We directly put the input in the lsfr
            Generally, at the beginning, the input correspond
            to the xoring of the uid, key and nonce Nt """
            self.cipher = input
        else:
            """ We update the state of the lfsr by
            xoring the lfsr with the input. For the moment,
            the feedback bits generated from g(x) are 
            not taken in account. But it should be at the 
            initialization step only ... """ 
            self.cipher = self.cipher ^ input

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
    def __init__(self, uid, key, initial_prng):
        """ A tag has an uid, a key and the crypto1"""
        self.uid = uid
        self.key = key
        Crypto1.__init__(self, key, initial_prng)

    def __str__(self):
        """ Informations about the tag """
        return "UID {0}, Key {1}, Cipher {2}, PRNG {3}".format(hex(self.uid), 
            hex(self.key), hex(self.cipher), hex(self.prng))

uid = 0xc2a82df4
key = 0xa0b1c2d3f4
initial_prng = 0x104A #0001000001001010

# Create a tag
card = Tag(uid, key, initial_prng)
print card

""" Generate nonce the initial nonce Nt. If we 
repeat the same operation 65535 times, we will 
obtain the same initial Nonce. """
Nt = card.suc_nonce()

""" Now the tag send the nonce Nt to the reader, it will be use 
to feed its cipher, plus the uid and the key sector, like 
the tag did with its own. The 48-bit LFSR will be in the 
same state for both, the tag and the reader. Like that, they
can communicate with each other correctly. The Nonce Nt
will be send in the reverse order, the least significant 
bit first (LSB)(on the left) """

# Synchronize the 48-bit LFSR with uid, key and Nonce Nt
print "Cipher state {0}".format(hex(card.cipher))
card.update_cipher(uid ^ key ^ Nt)
print "Cipher state {0}".format(int_to_hex(card.cipher))


""" Now it is time to generate the first keystream ks1. """
