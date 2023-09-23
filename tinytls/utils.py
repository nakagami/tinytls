##############################################################################
# Copyright (c) 2021, 2023 Hajime Nakagami<nakagami@gmail.com>
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
import hashlib


def pad16(n):
    "16 bytes alignment padding bytes"
    if n % 16:
        return b'\x00' * (16 - (n % 16))
    else:
        return b""


def urandom(n):
    "n bytes random bytes"
    try:
        import os
        return os.urandom(n)
    except AttributeError:
        import random
        return bytes([random.getrandbits(8) for _ in range(n)])


def bytes_to_bint(b):
    "Convert bytes to big endian int."
    n = 0
    for c in b:
        n <<= 8
        n += c
    return n


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
    return bytes(b)


def hmac_sha256(key, msg):
    try:
        import hmac
        return hmac.new(key, msg, hashlib.sha256).digest()
    except ImportError:     # MircroPython
        pad_key = key + b'\x00' * (64 - (len(key) % 64))
        ik = bytes([0x36 ^ b for b in pad_key])
        ok = bytes([0x5c ^ b for b in pad_key])
        return hashlib.sha256(ok + hashlib.sha256(ik+msg).digest()).digest()
