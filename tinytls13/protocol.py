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
from tinytls13 import utils

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

# extension type
supported_groups = b"\x00\x0a"      # 10
supported_versions = b"\x00\x2b"    # 43
signature_algorithms = b"\x00\x0d"  # 13
key_share = b"\x00\x33"             # 51

# signature schema
rsa_pss_rsae_sha256 = b"\x08\x04"
rsa_pss_rsae_sha384 = b"\x08\x05"
rsa_pss_rsae_sha512 = b"\x08\x06"

# key exchange method
key_exchange_x25519 = b"\x00\x1d"


def read_content(sock):
    head = sock.recv(5)
    ln = utils.bytes_to_bint(head[-2:])
    message = sock.recv(ln)
    return head, message


def parse_server_hello(data):
    assert data[:1] == server_hello
    ln = utils.bytes_to_bint(data[1:4])
    assert len(data) == ln + 4
    assert data[4:6] == TLS12
    _ = data[6:6+32]                    # skip random
    assert data[6+32:6+33] == b'\x00'   # legacy_session_id_echo
    assert data[6+33:6+35] == TLS_CHACHA20_POLY1305_SHA256
    assert data[6+35:6+36] == b'\x00'   # legacy_compression_methods (is nothing)

    ln = utils.bytes_to_bint(data[6+36:6+38])
    extensions = data[6+38:]
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


def client_hello_message(pub_key):
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
    extensions += supported_versions + b"\x00\x03" + b"\x02" + TLS13
    extensions += supported_groups + b"\x00\x04" + b"\x00\x02" + key_exchange_x25519
    extensions += (
        signature_algorithms + b"\x00\x08" + b"\x00\x06" +
        rsa_pss_rsae_sha256 + rsa_pss_rsae_sha384 + rsa_pss_rsae_sha512
    )
    extensions += (
        key_share + b"\x00\x26" + b"\x00\x24" + key_exchange_x25519 +
        utils.bint_to_bytes(len(pub_key), 2) + pub_key
    )
    base += utils.bint_to_bytes(len(extensions), 2) + extensions

    return client_hello + utils.bint_to_bytes(len(base), 3) + base


def finish_message(verify_data):
    return finished + utils.bint_to_bytes(len(verify_data), 3) + verify_data


def wrap_handshake(message):
    return handshake + TLS12 + utils.bint_to_bytes(len(message), 2) + message


def wrap_encrypted(encrypted):
    return application_data + TLS12 + utils.bint_to_bytes(len(encrypted), 2) + encrypted
