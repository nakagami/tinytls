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
from tinytls13 import hkdf
from tinytls13 import x25519
from tinytls13.poly1305 import ChaCha20Poly1305


class TLSContext:
    def __init__(self, client_private):
        self.client_private = client_private
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
        secret = hkdf.HKDF_extract(secret, psk)
        self.early_secret = secret

        # handshake secret
        secret = hkdf.derive_secret(secret, b'derived', b'')
        secret = hkdf.HKDF_extract(secret, self.shared_key)
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
        secret = hkdf.HKDF_extract(secret, label)
        self.master_secret = secret

        self.client_app_traffic_secret = hkdf.derive_secret(secret, b'c ap traffic', messages)
        self.server_app_traffic_secret = hkdf.derive_secret(secret, b's ap traffic', messages)

        client_app_write_key, client_app_write_iv = hkdf.gen_key_and_iv(self.client_app_traffic_secret)
        server_app_write_key, server_app_write_iv = hkdf.gen_key_and_iv(self.server_app_traffic_secret)

        self.client_app_data_crypto = ChaCha20Poly1305(client_app_write_key, client_app_write_iv)
        self.server_app_data_crypto = ChaCha20Poly1305(server_app_write_key, server_app_write_iv)
