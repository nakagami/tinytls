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
import sys
import hashlib
import binascii
import random


def bs(byte_array):
    "int (as character) list to bytes"
    return bytes(bytearray(byte_array))


def pad16(n):
    "16 bytes alignment padding bytes"
    if n % 16:
        return b'\x00' * (16 - (n % 16))
    else:
        return b""


def trim_pad(b):
    "trim padding \x00"
    i = len(b) - 1
    while byte_to_int(b[i]) == 0:
        i -= 1
    return b[:i+1]


def urandom(n):
    "n bytes random bytes"
    try:
        import os
        return os.urandom(n)
    except AttributeError:
        return bs([random.getrandbits(8) for _ in range(n)])


def byte_to_int(c):
    if sys.version_info[0] == 3:
        return c
    else:
        return ord(c)


def bytes_to_int(b):
    "Convert bytes to little endian int."
    n = 0
    for c in reversed(b):
        n <<= 8
        n += byte_to_int(c)
    return n


def bytes_to_bint(b):
    "Convert bytes to big endian int."
    n = 0
    for c in b:
        n <<= 8
        n += byte_to_int(c)
    return n


def int_to_bytes(val, nbytes):
    "Convert int val to nbytes little endian bytes."
    v = abs(val)
    byte_array = []
    for n in range(nbytes):
        byte_array.append((v >> (8 * n)) & 0xff)
    if val < 0:
        for i in range(nbytes):
            byte_array[i] = ~byte_array[i] + 256
        byte_array[0] += 1
        for i in range(nbytes):
            if byte_array[i] == 256:
                byte_array[i] = 0
                byte_array[i+1] += 1

    return bs(byte_array)


def bint_to_bytes(val, nbytes):
    "Convert int val to nbytes big endigan bytes."
    v = abs(val)
    b = []
    for n in range(nbytes):
        b.append((v >> (8 * (nbytes - n - 1)) & 0xff))
    if val < 0:
        for i in range(nbytes):
            b[i] = ~b[i] + 256
        b[-1] += 1
        for i in range(nbytes):
            if b[nbytes - i - 1] == 256:
                b[nbytes - i - 1] = 0
                b[nbytes - i - 2] += 1
    return bs(b)


def xor_byte(c1, c2):
    return bytes(bytearray([(byte_to_int(c1) ^ byte_to_int(c2))]))


def xor_bytes(b1, b2):
    assert len(b1) == len(b2)
    if not isinstance(b1, bytearray):
        b1 = bytearray(b1)
    if not isinstance(b2, bytearray):
        b2 = bytearray(b2)
    return bs([x ^ y for (x, y) in zip(b1, b2)])


def pack_x25519(n):
    return bytes(bytearray([((n >> (8 * i)) & 255) for i in range(32)]))


# Equivalent to RFC7748 decodeUCoordinate followed by decodeLittleEndian
def unpack_x25519(s):
    if len(s) != 32:
        raise ValueError('Invalid Curve25519 scalar (len=%d)' % len(s))
    t = sum([byte_to_int(s[i]) << (8 * i) for i in range(31)])
    t += (byte_to_int(s[31]) & 0x7f) << 248
    return t


def decode_scalar_x25519(k):
    b = [byte_to_int(b) for b in k]
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return sum([b[i] << 8 * i for i in range(32)])


def hmac_sha256(key, msg):
    try:
        import hmac
        return hmac.new(key, msg, hashlib.sha256).digest()
    except ImportError:     # MircroPython
        pad_key = key + b'\x00' * (64 - (len(key) % 64))
        ik = bytes([0x36 ^ b for b in pad_key])
        ok = bytes([0x5c ^ b for b in pad_key])
        return hashlib.sha256(ok + hashlib.sha256(ik+msg).digest()).digest()
