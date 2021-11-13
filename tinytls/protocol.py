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
from tinytls import hkdf
from tinytls import utils

# protocol version
TLS12 = b"\x03\x03"
TLS13 = b"\x03\x04"

# content type
change_cipher_spec = b"\x14"
alert = b"\x15"
handshake = b"\x16"
application_data = b"\x17"

# cipher suites
TLS_CHACHA20_POLY1305_SHA256 = b"\x13\x03"
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = b"\x00\xFF"

# handshake type
client_hello = b"\x01"
server_hello = b"\x02"
new_session_ticket = b"\x04"
end_of_early_data = b"\x05"
encrypted_extensions = b"\x08"
certificate = b"\x0b"
certificate_request = b"\x0d"
certificate_verify = b"\x0f"
finished = b"\x14"
key_update = b"\x18"
message_hash = b"\xfe"

# alert description
close_notify = b"\x00"
handshake_failure = b"\x28"

# extension type
server_name = b"\x00\x00"               # 0
supported_groups = b"\x00\x0a"          # 10
signature_algorithms = b"\x00\x0d"      # 13
srp = b"\x00\x0c"                       # 12
encrypt_then_mac = b"\x00\x16"          # 22
extended_master_secret = b"\x00\x17"    # 23
session_ticket = b"\x00\x23"            # 35
supported_versions = b"\x00\x2b"        # 43
psk_kex_modes = b"\x00\x2d"             # 45
key_share = b"\x00\x33"                 # 51

# signature schema

# RSASSA-PKCS1-v1_5 algorithms
rsa_pkcs1_sha256 = b"\x04\x01"
rsa_pkcs1_sha384 = b"\x05\x01"
rsa_pkcs1_sha512 = b"\x06\x01"

# ECDSA algorithms
ecdsa_secp256r1_sha256 = b"\x04\x03"
ecdsa_secp384r1_sha384 = b"\x05\x03"
ecdsa_secp512r1_sha512 = b"\x06\x03"

# RSASSA-PSS algorithms with public key OID rsaEncryption
rsa_pss_rsae_sha256 = b"\x08\x04"
rsa_pss_rsae_sha384 = b"\x08\x05"
rsa_pss_rsae_sha512 = b"\x08\x06"
# EdDSA algorithms
ed25519 = b"\x08\x07"
ed448 = b"\x08\x08"

# RSASSA-PSS algorithms with public key OID RSASSA-PSS
rsa_pss_pss_sha256 = b"\x08\x09"
rsa_pss_pss_sha384 = b"\x08\x0a"
rsa_pss_pss_sha512 = b"\x08\x0b"

signature_schemas = b"".join([
    rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512,
    ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp512r1_sha512,
    rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512,
    ed25519, ed448,
    rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512,
])


# key exchange method
key_exchange_x25519 = b"\x00\x1d"


def encrypted_app_data(data, content_type, encrypter):
    data += content_type
    message_pad = data + utils.pad16(len(data))
    tag_size = 16
    aad = application_data + TLS12 + utils.bint_to_bytes(len(message_pad) + tag_size, 2)
    encrypted = encrypter.encrypt_and_tag(message_pad, aad)
    return application_data + TLS12 + utils.bint_to_bytes(len(encrypted), 2) + encrypted


def read_content(sock):
    head = sock.recv(5)
    ln = utils.bytes_to_bint(head[-2:])
    message = b""
    while (ln):
        buf = sock.recv(ln)
        ln -= len(buf)
        message += buf

    return head, message


def parse_server_hello(data):
    assert data[:1] == server_hello
    ln = utils.bytes_to_bint(data[1:4])
    assert len(data) == ln + 4

    i = 4
    assert data[i:i+2] == TLS12
    i += 2
    _ = data[i:i+32]                        # skip random
    i += 32
    legacy_session_id_len = utils.bytes_to_bint(data[i:i+1])
    i += 1
    _ = data[i:i+legacy_session_id_len]     # legacy_session_id
    i += legacy_session_id_len
    assert data[i:i+2] == TLS_CHACHA20_POLY1305_SHA256
    i += 2
    assert data[i:i+1] == b'\x00'   # legacy_compression_methods (is nothing)
    i += 1
    ln = utils.bytes_to_bint(data[i:i+2])
    i += 2
    extensions = data[i:]
    assert ln == len(extensions)

    server_public = b""
    while len(extensions):
        extension_type = extensions[:2]
        extension_ln = utils.bytes_to_bint(extensions[2:4])
        extension_value = extensions[4:4 + extension_ln]
        if extension_type == key_share:
            extension_value[:2] == key_exchange_x25519
            assert utils.bytes_to_bint(extension_value[2:4]) == 32
            server_public = extension_value[4:]
        extensions = extensions[4 + extension_ln:]

    assert len(server_public) == 32
    return server_public


def client_hello_message(pub_key, server_hostname=None):
    # https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2
    base = TLS12            # legacy version
    base += utils.urandom(32)     # random
    base += b"\x00"          # legacy_session_id (zero length vector)

    # cipher suites
    cipher_suites = TLS_CHACHA20_POLY1305_SHA256 + TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    base += utils.bint_to_bytes(len(cipher_suites), 2) + cipher_suites

    # legacy_compression_methods (is nothing)
    base += b"\x01\x00"

    # extensions
    extensions = b""
    if server_hostname:
        b = server_hostname.encode()
        b = utils.bint_to_bytes(len(b), 1) + b
        b = b'\x00\x00' + b
        b = utils.bint_to_bytes(len(b), 2) + b
        b = utils.bint_to_bytes(len(b), 2) + b
        extensions = server_name + b
    extensions += supported_groups + b"\x00\x04" + b"\x00\x02" + key_exchange_x25519
    # extensions += session_ticket + b"\x00\x00"
    extensions += encrypt_then_mac + b"\x00\x00"
    # extensions += extended_master_secret + b"\x00\x00"
    b = utils.bint_to_bytes(len(signature_schemas), 2) + signature_schemas
    b = utils.bint_to_bytes(len(b), 2) + b
    extensions += signature_algorithms + b
    extensions += supported_versions + b"\x00\x03" + b"\x02" + TLS13
    # extensions += psk_kex_modes + b"\x00\x02\x01\x01"
    extensions += (
        key_share + b"\x00\x26" + b"\x00\x24" + key_exchange_x25519 +
        utils.bint_to_bytes(len(pub_key), 2) + pub_key
    )

    base += utils.bint_to_bytes(len(extensions), 2) + extensions
    return client_hello + utils.bint_to_bytes(len(base), 3) + base


def finished_verify_data(messages, secret):
    finished_key = hkdf.HKDF_expand_label(secret, b'finished', b'', 32)
    return utils.hmac_sha256(finished_key, hashlib.sha256(messages).digest())


def finished_message(ctx):
    verify_data = finished_verify_data(ctx.get_messages(), ctx.client_hs_traffic_secret)
    return finished + utils.bint_to_bytes(len(verify_data), 3) + verify_data


def close_notify_message():
    return b'\x02' + close_notify
