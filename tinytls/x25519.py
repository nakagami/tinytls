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
# I referred to https://asecuritysite.com/encryption/python_25519ecdh
from tinytls import utils


P = 2 ** 255 - 19
A24 = 121665


def cswap(swap, x_2, x_3):
    dummy = swap * ((x_2 - x_3) % P)
    x_2 = x_2 - dummy
    x_2 %= P
    x_3 = x_3 + dummy
    x_3 %= P
    return (x_2, x_3)


def pack_x25519(n):
    return bytes(bytearray([((n >> (8 * i)) & 255) for i in range(32)]))


# Equivalent to RFC7748 decodeUCoordinate followed by decodeLittleEndian
def unpack_x25519(s):
    if len(s) != 32:
        raise ValueError('Invalid Curve25519 scalar (len=%d)' % len(s))
    t = sum([utils.byte_to_int(s[i]) << (8 * i) for i in range(31)])
    t += (utils.byte_to_int(s[31]) & 0x7f) << 248
    return t


def decode_scalar_x25519(k):
    b = [utils.byte_to_int(b) for b in k]
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return sum([b[i] << 8 * i for i in range(32)])


# Based on https://tools.ietf.org/html/rfc7748
def x25519(k, u):
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t

        A = x_2 + z_2
        A %= P

        AA = A * A
        AA %= P

        B = x_2 - z_2
        B %= P

        BB = B * B
        BB %= P

        E = AA - BB
        E %= P

        C = x_3 + z_3
        C %= P

        D = x_3 - z_3
        D %= P

        DA = D * A
        DA %= P

        CB = C * B
        CB %= P

        x_3 = ((DA + CB) % P)**2
        x_3 %= P

        z_3 = x_1 * (((DA - CB) % P)**2) % P
        z_3 %= P

        x_2 = AA * BB
        x_2 %= P

        z_2 = E * ((AA + (A24 * E) % P) % P)
        z_2 %= P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)

    return (x_2 * pow(z_2, P - 2, P)) % P


def clamp(n):
    n &= ~7
    n &= ~(128 << 8 * 31)
    n |= 64 << 8 * 31
    return n


# Return nP
def multscalar(n, p):
    n = clamp(decode_scalar_x25519(n))
    p = unpack_x25519(p)
    return pack_x25519(x25519(n, p))


# Start at x=9. Find point n times x-point
def base_point_mult(n):
    n = clamp(decode_scalar_x25519(n))
    return pack_x25519(x25519(n, 9))
