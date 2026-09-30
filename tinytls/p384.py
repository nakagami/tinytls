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
"""NIST P-384 (secp384r1) elliptic curve Diffie-Hellman
https://tools.ietf.org/html/rfc8446#section-4.2.8.2
"""
from tinytls import utils

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
A = P - 3
B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
Gx = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
Gy = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F


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
        k = utils.bytes_to_bint(utils.urandom(48))
        if 1 <= k < N:
            return utils.bint_to_bytes(k, 48)


def multscalar(n, p):
    if isinstance(n, bytes):
        n = utils.bytes_to_bint(n)
    if len(p) != 97 or p[:1] != b'\x04':
        raise ValueError('Invalid P-384 public key')
    x = utils.bytes_to_bint(p[1:49])
    y = utils.bytes_to_bint(p[49:97])
    if (y * y - (x * x * x + A * x + B)) % P != 0:
        raise ValueError('Point not on P-384 curve')
    pt = _jacobian_mult((x, y, 1), n, P, A)
    x_aff, y_aff = _to_affine(pt, P)
    if x_aff == 0 and y_aff == 0:
        raise ValueError('Result is point at infinity')
    return utils.bint_to_bytes(x_aff, 48)


def base_point_mult(n):
    if isinstance(n, bytes):
        n = utils.bytes_to_bint(n)
    pt = _jacobian_mult((Gx, Gy, 1), n, P, A)
    x, y = _to_affine(pt, P)
    return b'\x04' + utils.bint_to_bytes(x, 48) + utils.bint_to_bytes(y, 48)
