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
import hashlib
from tinytls import utils


def HKDF_expand(prk, info, ln):
    # HKDF (https://tools.ietf.org/html/rfc5869#section-2.3)
    q, r = divmod(ln, 32)
    n = q + bool(r)
    t = bytearray()
    t_prev = bytearray()
    for x in range(1, n+2):
        t += t_prev
        t_prev = utils.hmac_sha256(prk, t_prev + info + bytearray([x]))
    return bytes(t[:ln])


def HKDF_expand_label(secret, label, hash_value, length):
    # HKDF-Expand-Label (https://tools.ietf.org/html/rfc8446#section-7.1)
    label = b'tls13 ' + label
    hkdf_label = utils.bint_to_bytes(length, 2)
    hkdf_label += utils.bint_to_bytes(len(label), 1) + label
    hkdf_label += utils.bint_to_bytes(len(hash_value), 1) + hash_value
    return HKDF_expand(secret, hkdf_label, length)


def derive_secret(secret, label, messages):
    # Derive-Secret (https://tools.ietf.org/html/rfc8446#section-7.1)
    return HKDF_expand_label(secret, label, hashlib.sha256(messages).digest(), 32)


def gen_key_and_iv(secret):
    return HKDF_expand_label(secret, b'key', b'', 32), HKDF_expand_label(secret, b'iv',  b'', 12)
