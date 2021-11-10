##############################################################################
# Copyright (c) 2021 Hajime Nakagami<nakagami@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
##############################################################################
import math
from tinytls import utils
from tinytls.chacha20 import ChaCha20


def poly1305_mac(msg, key):
    assert len(key) == 32
    r = utils.bytes_to_int(key[:16]) & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = utils.bytes_to_int(key[16:])
    a = 0  # a is the accumulator
    p = (1 << 130) - 5
    for i in range(1, int(math.ceil(float(len(msg))/16)) + 1):
        n = utils.bytes_to_int(msg[(i-1)*16: i*16] + b'\x01')
        a += n
        a = (r * a) % p
    a += s
    return utils.int_to_bytes(a, 16)


def poly1305_key_gen(key, nonce):
    chacha20 = ChaCha20(key, nonce)
    return chacha20.block[:32]


def chacha20_aead_encrypt(aad, key, nonce, plaintext):
    otk = poly1305_key_gen(key, nonce)
    chacha20 = ChaCha20(key, nonce, 1)
    ciphertext = chacha20.translate(plaintext)
    mac_data = aad + utils.pad16(len(aad))
    mac_data += ciphertext + utils.pad16(len(ciphertext))
    mac_data += utils.int_to_bytes(len(aad), 8)
    mac_data += utils.int_to_bytes(len(ciphertext), 8)
    tag = poly1305_mac(mac_data, otk)
    return (ciphertext, tag)


def chacha20_aead_decrypt(aad, key, nonce, ciphertext):
    otk = poly1305_key_gen(key, nonce)
    chacha20 = ChaCha20(key, nonce, 1)
    plaintext = chacha20.translate(ciphertext)
    mac_data = aad + utils.pad16(len(aad))
    mac_data += ciphertext + utils.pad16(len(ciphertext))
    mac_data += utils.int_to_bytes(len(aad), 8)
    mac_data += utils.int_to_bytes(len(ciphertext), 8)
    tag = poly1305_mac(mac_data, otk)
    return (plaintext, tag)


class ChaCha20Poly1305:
    def __init__(self, key, nonce):
        self.key = key
        self.nonce = nonce
        self.seq_number = 0

    def get_nonce(self):
        nonce = utils.xor_bytes(self.nonce, utils.bint_to_bytes(self.seq_number, len(self.nonce)))
        self.seq_number += 1
        return nonce

    def encrypt_and_tag(self, plaintext, aad):
        nonce = self.get_nonce()
        ciphertext, tag = chacha20_aead_encrypt(aad, self.key, nonce, plaintext)
        return ciphertext + tag

    def decrypt_and_verify(self, ciphertext, aad):
        mac, ciphertext = ciphertext[-16:], ciphertext[:-16]
        nonce = self.get_nonce()
        plaintext, tag = chacha20_aead_decrypt(aad, self.key, nonce, ciphertext)

        bad_tag = len(tag) != len(mac)
        result = 0
        for x, y in zip(bytearray(tag), bytearray(mac)):
            result |= x ^ y
        if result != 0:
            bad_tag = True
        if bad_tag:
            raise Exception('Poly1305: Bad Tag!')

        plaintext = utils.trim_pad(plaintext)
        return plaintext[:-1], plaintext[-1:]
