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
from tinytls import protocol
from tinytls import hkdf
from tinytls import x25519
from tinytls import utils
from tinytls.chacha20poly1305 import ChaCha20Poly1305


VERSION = (0, 1, 1)
__version__ = '%s.%s.%s' % VERSION


class TLSContext:
    def __init__(self):
        self.client_private = utils.urandom(32)
        self.client_public = x25519.base_point_mult(self.client_private)
        self.messages = []

    def get_messages(self):
        return b''.join(self.messages)

    def append_message(self, message):
        self.messages.append(message)

    def set_key_exchange(self, server_public):
        self.shared_key = x25519.multscalar(self.client_private, server_public)

    def key_schedule_in_handshake(self):
        messages = self.get_messages()
        secret = psk = b'\x00' * 32

        # early secret
        secret = utils.hmac_sha256(secret, psk)
        self.early_secret = secret

        # handshake secret
        secret = hkdf.derive_secret(secret, b'derived', b'')
        secret = utils.hmac_sha256(secret, self.shared_key)
        self.handshake_secret = secret

        self.client_hs_traffic_secret = hkdf.derive_secret(secret, b'c hs traffic', messages)
        self.server_hs_traffic_secret = hkdf.derive_secret(secret, b's hs traffic', messages)

        client_write_key, client_write_iv = hkdf.gen_key_and_iv(self.client_hs_traffic_secret)
        server_write_key, server_write_iv = hkdf.gen_key_and_iv(self.server_hs_traffic_secret)

        self.client_traffic_crypto = ChaCha20Poly1305(client_write_key, client_write_iv)
        self.server_traffic_crypto = ChaCha20Poly1305(server_write_key, server_write_iv)

    def key_schedule_in_app_data(self):
        messages = self.get_messages()

        # master secret
        label = b'\x00' * 32
        secret = self.handshake_secret
        secret = hkdf.derive_secret(secret, b'derived', b'')
        secret = utils.hmac_sha256(secret, label)
        self.master_secret = secret

        self.client_app_traffic_secret = hkdf.derive_secret(secret, b'c ap traffic', messages)
        self.server_app_traffic_secret = hkdf.derive_secret(secret, b's ap traffic', messages)

        client_app_write_key, client_app_write_iv = hkdf.gen_key_and_iv(self.client_app_traffic_secret)
        server_app_write_key, server_app_write_iv = hkdf.gen_key_and_iv(self.server_app_traffic_secret)

        self.client_app_data_crypto = ChaCha20Poly1305(client_app_write_key, client_app_write_iv)
        self.server_app_data_crypto = ChaCha20Poly1305(server_app_write_key, server_app_write_iv)

    def wrap_socket(self, sock, server_hostname=None):
        tls_socket = TLSSocket(self, sock, server_hostname)
        tls_socket.client_hello()
        tls_socket.server_hello()
        tls_socket.server_handshake()
        tls_socket.send_finished()
        tls_socket.key_schedule()

        return tls_socket


class TLSSocket:
    def __init__(self, ctx, sock, server_hostname):
        self.ctx = ctx
        self.sock = sock
        self.server_hostname = server_hostname
        self.read_buf = b''

    def _sendall(self, b):
        while b:
            ln = self.sock.send(b)
            b = b[ln:]

    def client_hello(self):
        message = protocol.client_hello_message(self.ctx.client_public, self.server_hostname)
        self.ctx.append_message(message)
        client_hello_handshake = protocol.handshake + protocol.TLS12 + utils.bint_to_bytes(len(message), 2) + message
        self._sendall(client_hello_handshake)

    def server_hello(self):
        head, message = protocol.read_content(self.sock)
        if (head[:3] == protocol.alert + protocol.TLS12 and message == protocol.server_hello + protocol.handshake_failure):
            raise Exception("alert handshake failure")
        assert head[:3] == protocol.handshake + protocol.TLS12
        assert message[:1] == protocol.server_hello
        self.ctx.append_message(message)
        server_public = protocol.parse_server_hello(message)
        self.ctx.set_key_exchange(server_public)
        self.ctx.key_schedule_in_handshake()

    def server_handshake(self):
        finished = False
        while not finished:
            head, message = protocol.read_content(self.sock)
            if head[:1] == protocol.change_cipher_spec:
                # ignore change cipher spec
                continue
            # recieve application_data
            assert head[:3] == protocol.application_data + protocol.TLS12
            plaindata, content_type = self.ctx.server_traffic_crypto.decrypt_and_verify(message, head)
            while plaindata:
                _ = plaindata[:1]       # handshake type
                ln = utils.bytes_to_bint(plaindata[1:4])
                segment, plaindata = plaindata[:ln+4], plaindata[ln+4:]
                if segment[:1] == protocol.finished:
                    # recieve Finishied
                    verify_data = segment[4:]
                    assert len(verify_data) == 32
                    expected_verify_data = protocol.finished_verify_data(
                        self.ctx.get_messages(), self.ctx.server_hs_traffic_secret
                    )
                    assert verify_data == expected_verify_data
                    finished = True
                self.ctx.append_message(segment)

    def key_schedule(self):
        self.ctx.key_schedule_in_app_data()

    def send_finished(self):
        self._sendall(
            protocol.encrypted_app_data(
                protocol.finished_message(self.ctx), protocol.handshake, self.ctx.client_traffic_crypto
            )
        )

    def send_alert(self):
        self._sendall(
            protocol.encrypted_app_data(protocol.close_notify_message(), protocol.alert, self.ctx.client_app_data_crypto)
        )

    def send(self, data):
        self._sendall(
            protocol.encrypted_app_data(data, protocol.application_data, self.ctx.client_app_data_crypto)
        )

    def recv(self, ln):
        if not self.read_buf:
            head, message = protocol.read_content(self.sock)
            plaindata, content_type = self.ctx.server_app_data_crypto.decrypt_and_verify(message, head)
            self.read_buf = plaindata
        r, self.read_buf = self.read_buf[:ln], self.read_buf[ln:]
        return r

    def __enter__(self):
        return self

    def __exit__(self, exc, value, traceback):
        self.send_alert()


def create_default_context():
    return TLSContext()


def wrap_socket(sock, server_hostname=None):
    return create_default_context().wrap_socket(sock, server_hostname)
