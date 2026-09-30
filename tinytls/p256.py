##############################################################################
# Copyright (c) 2021, 2023, 2026 Hajime Nakagami<nakagami@gmail.com>
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
"""NIST P-256 (secp256r1 / prime256v1) elliptic curve Diffie-Hellman
https://tools.ietf.org/html/rfc8446#section-4.2.8.2
"""
from tinytls import utils

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _jacobian_add(p1, p2, p, a):
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1

    z1z1 = (z1 * z1) % p
    z2z2 = (z2 * z2) % p
    u1 = (x1 * z2z2) % p
    u2 = (x2 * z1z1) % p
    s1 = (y1 * z2 * z2z2) % p
    s2 = (y2 * z1 * z1z1) % p

    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jacobian_double(p1, p, a)

    h = (u2 - u1) % p
    i = (4 * h * h) % p
    j = (h * i) % p
    r = (2 * (s2 - s1)) % p
    v = (u1 * i) % p
    x3 = (r * r - j - 2 * v) % p
    y3 = (r * (v - x3) - 2 * s1 * j) % p
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % p
    return (x3, y3, z3)


def _jacobian_double(p1, p, a):
    x1, y1, z1 = p1
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)

    delta = (z1 * z1) % p
    gamma = (y1 * y1) % p
    beta = (x1 * gamma) % p
    alpha = (3 * (x1 - delta) * (x1 + delta)) % p
    x3 = (alpha * alpha - 8 * beta) % p
    z3 = ((y1 + z1) ** 2 - gamma - delta) % p
    y3 = (alpha * (4 * beta - x3) - 8 * gamma * gamma) % p
    return (x3, y3, z3)


def _jacobian_mult(p1, scalar, p, a):
    res = (0, 1, 0)
    temp = p1
    while scalar > 0:
        if scalar & 1:
            res = _jacobian_add(res, temp, p, a)
        temp = _jacobian_double(temp, p, a)
        scalar >>= 1
    return res


def _to_affine(p1, p):
    x, y, z = p1
    if z == 0:
        return (0, 0)
    z_inv = pow(z, p - 2, p)
    z_inv2 = (z_inv * z_inv) % p
    z_inv3 = (z_inv2 * z_inv) % p
    return ((x * z_inv2) % p, (y * z_inv3) % p)


def generate_private_key():
    while True:
        k = utils.bytes_to_bint(utils.urandom(32))
        if 1 <= k < N:
            return utils.bint_to_bytes(k, 32)


def multscalar(n, p):
    if isinstance(n, bytes):
        n = utils.bytes_to_bint(n)
    if len(p) != 65 or p[:1] != b'\x04':
        raise ValueError('Invalid P-256 public key')
    x = utils.bytes_to_bint(p[1:33])
    y = utils.bytes_to_bint(p[33:65])
    if (y * y - (x * x * x + A * x + B)) % P != 0:
        raise ValueError('Point not on P-256 curve')
    pt = _jacobian_mult((x, y, 1), n, P, A)
    x_aff, y_aff = _to_affine(pt, P)
    if x_aff == 0 and y_aff == 0:
        raise ValueError('Result is point at infinity')
    return utils.bint_to_bytes(x_aff, 32)


def base_point_mult(n):
    if isinstance(n, bytes):
        n = utils.bytes_to_bint(n)
    pt = _jacobian_mult((Gx, Gy, 1), n, P, A)
    x, y = _to_affine(pt, P)
    return b'\x04' + utils.bint_to_bytes(x, 32) + utils.bint_to_bytes(y, 32)
