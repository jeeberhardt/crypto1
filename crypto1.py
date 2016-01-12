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

    def get_initial_nonce(self):
        """ Function to generate the initial nonce based
        on the 16 bits LFSR initial state. Since the nonce
        is 32 bits and the LFSR is only 16 bits, the first 
        half of the nonce (or the initial prng state) will
        define the second half. The 16 bits LFSR shifts to
        the left. The new feedback bit is added on the right
        and the bit on the left is discarded. 
        LFSR: https://www.youtube.com/watch?v=sKUhFpVxNWc"""

        #First we will initiate the nonce with the prng.
        bit_nonce = int_to_bitstr(self.prng, 16)

        """ Then we generate the second part by taking only 
        the last 16 bits until we have 32 bits in total. """
        for i in range(16):
            bit_nonce += self.prng_feedback(bit_nonce[i:i+16])

        """ The new state of the prng will be the last 16 bits
        of the nonce, because we discarded 16 bits during the
        feedback loop. The initial nonce has 32 bits now. """
        bit_prng = bit_nonce[16:]

        self.prng = bitstr_to_int(bit_prng)
        self.nonce = bitstr_to_int(bit_nonce)

        return self.nonce

    def suc_nonce(self, nonce = None):
        """ Function to generate the successor nonce based 
        on the second half (16 bits long) of the nonce. """

        # if we don't provide a nonce. We will use the internal one
        if nonce is None:
            nonce = self.nonce

        # We convert the nonce in bit in order to work on it
        bit_nonce = int_to_bitstr(nonce, 32)

        """ Generate the feedback bit based on the nonce's 
        second half, because the last 16 bits of the nonce is
        identical to the 16 bits prng state. """
        fbit = self.prng_feedback(bit_nonce[16,:])

        # The left bit is discarded and the feedback bit is added
        nonce = bit_nonce[1:] + fbit

        # We will update the internal nonce/prng to the suc(nonce/prng)
        if nonce is None:

            # The internal prng is updated with the second part of the nonce
            self.prng = bitstr_to_int(bit_nonce[16,:])
            self.nonce = bitstr_to_int(bit_nonce)

            # Return nonce, it will be sent to the reader
            return self.nonce
        else:
            return bitstr_to_int(nonce)

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
        return ((a | b) ^ (a & d)) ^ (c & ((a ^ b) | d))

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

class Mifare(Crypto1):
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

print "\nCreation of the card and the reader"

# Create a tag with a uid, a key sector and initial prng state 
tag = Mifare(uid, key, initial_prng = 0x104A)
# Create a tag with uid (from the selected tag), key sector and initial prng state
reader = Mifare(uid, key, initial_prng = 0x108A)

print "Tag state           : {0}".format(tag)
print "Reader state        : {0}".format(reader)

""" Generate nonce the initial nonce Nt. If we 
repeat the same operation 65535 times, we will 
obtain the same initial Nonce. """
Nt = tag.get_initial_nonce()

""" Now the tag send the nonce Nt to the reader, it will be use 
to feed its cipher, plus the uid and the key sector, like 
the tag did with its own. The 48-bit LFSR will be in the 
same state for both, the tag and the reader. Like that, they
can communicate with each other correctly. The Nonce Nt
will be send in the reverse order, the least significant 
bit first (LSB)(on the left) """

# Feed the 48-bits tag and reader cipher with (uid xor Nt)
print "\nUpdate cipher state (reader - tag) - uid xor Nt"
old = int_to_hex(tag.cipher)
tag.update_cipher(uid ^ Nt)
print "Tag cipher state    : {0} --> {1}".format(old, int_to_hex(tag.cipher))
old = int_to_hex(reader.cipher)
reader.update_cipher(uid ^ Nt)
print "Reader cipher state : {0} --> {1}".format(old, int_to_hex(reader.cipher))

print "\nUpdate cipher state (reader) - Nr"
# Now the reader picks its own nonce Nr
Nr = reader.get_initial_nonce()
# And update its cipher with it
old = int_to_hex(reader.cipher)
reader.update_cipher(Nr)
print "Reader cipher state : {0} --> {1}".format(old, int_to_hex(reader.cipher))

print "\nGet the suc2(Nt) (reader)"
