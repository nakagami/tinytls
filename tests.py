import socket
import unittest
import tinytls
from tinytls import utils
from tinytls import protocol
from tinytls import x25519
from tinytls import chacha20poly1305
from tinytls import hkdf


def hex_to_bytes(s):
    "convert hex string to bytes"
    s = ''.join(s.split())
    if len(s) % 2:
        s = b'0' + s
    ia = [int(s[i:i+2], 16) for i in range(0, len(s), 2)]   # int array
    return bytes(bytearray(ia))


class TestProtocol(unittest.TestCase):
    def test_client_hello(self):
        private_key = b'\x00' * 32
        public_key = x25519.base_point_mult(private_key)
        data = protocol.client_hello_message(public_key)
        self.assertEqual(data[:6], hex_to_bytes("0100008c0303"))
        self.assertEqual(
            data[6+32:],
            hex_to_bytes("""
                            000004130300ff010000
                5f000a00040002001d00160000000d00
                1e001c04010501060104030503060308
                0408050806080708080809080a080b00
                2b0003020304003300260024001d0020
                2fe57da347cd62431528daac5fbb2907
                30fff684afc4cfc2ed90995f58cb3b74
            """)
        )


class TestX25519(unittest.TestCase):
    def test_x25519(self):
        a = utils.urandom(32)
        a_pub = x25519.base_point_mult(a)
        b = utils.urandom(32)
        b_pub = x25519.base_point_mult(b)
        self.assertEqual(x25519.multscalar(a, b_pub), x25519.multscalar(b, a_pub))

    def test_modulo(self):
        # There are older micropython implementations that get this calculation wrong
        # If this test fails, please upgrade your micropython version.
        self.assertEqual(
            3351951982485649274893506249551461531869841455148098344430890360929126892766387686103746101496463077066730197146548147517807404440828687420984717926233961 % 57896044618658097711785492504343953926634992332820282019728792003956564819949,
            128797905270015590400
        )


class TestChaCha20Poly1305(unittest.TestCase):
    def test_chacha20(self):
        key = hex_to_bytes("23AD52B15FA7EBDC4672D72289253D95DC9A4324FC369F593FDCC7733AD77617")
        nonce = hex_to_bytes("5A5F6C13C1F12653")
        enc = hex_to_bytes("6bd00ba222523f58de196fb471eea08d9fff95b5bbe6123dd3a8b9026ac0fa84")
        chacha = chacha20poly1305.ChaCha20(key, nonce)
        self.assertEqual(chacha.translate(enc), b'TMCTF{Whose_garden_is_internet?}')

        chacha1 = chacha20poly1305.ChaCha20(key, nonce, 123)
        enc = chacha1.translate(b'plain text')
        self.assertEqual(enc, hex_to_bytes("39df7fdfcdd66c56e762"))
        chacha2 = chacha20poly1305.ChaCha20(key, nonce, 123)
        plain = chacha2.translate(enc)
        self.assertEqual(plain, b'plain text')

    def test_poly1305_mac(self):
        msg = b'Cryptographic Forum Research Group'
        key = hex_to_bytes("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        tag = chacha20poly1305.poly1305_mac(msg, key)
        self.assertEqual(tag, hex_to_bytes("a8061dc1305136c6c22b8baf0c0127a9"))

    def test_poly1305_key_gen(self):
        key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = hex_to_bytes("000000000001020304050607")
        self.assertEqual(
            chacha20poly1305.poly1305_key_gen(key, nonce),
            hex_to_bytes("8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646")
        )

    def test_chacha20_aead_encrypt(self):
        plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
        key = hex_to_bytes('''
            80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
            90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f
        ''')
        iv = b'@ABCDEFG'
        constant = hex_to_bytes("07000000")
        nonce = constant + iv
        ciphertext, tag = chacha20poly1305.chacha20_aead_encrypt(aad, key, nonce, plaintext)

        expected_ciphertext = hex_to_bytes('''
            d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
            a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
            3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
            1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
            92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
            fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
            3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
            61 16
        ''')
        expected_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691")

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(tag, expected_tag)

    def test_chacha20poly1305_aead_decrypt(self):
        aad = hex_to_bytes('f33388860000000000004e91')
        key = hex_to_bytes('''
            1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0
            47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0
        ''')
        nonce = hex_to_bytes('000000000102030405060708')
        ciphertext = hex_to_bytes('''
            64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd
            5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2
            4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0
            bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf
            33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81
            14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55
            97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38
            36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4
            b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9
            90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e
            af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a
            0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a
            0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e
            ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10
            49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30
            30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29
            a6 ad 5c b4 02 2b 02 70 9b
        ''')

        plaintext, tag = chacha20poly1305.chacha20_aead_decrypt(aad, key, nonce, ciphertext)

        expected_plaintext = hex_to_bytes('''
            49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 73 20
            61 72 65 20 64 72 61 66 74 20 64 6f 63 75 6d 65
            6e 74 73 20 76 61 6c 69 64 20 66 6f 72 20 61 20
            6d 61 78 69 6d 75 6d 20 6f 66 20 73 69 78 20 6d
            6f 6e 74 68 73 20 61 6e 64 20 6d 61 79 20 62 65
            20 75 70 64 61 74 65 64 2c 20 72 65 70 6c 61 63
            65 64 2c 20 6f 72 20 6f 62 73 6f 6c 65 74 65 64
            20 62 79 20 6f 74 68 65 72 20 64 6f 63 75 6d 65
            6e 74 73 20 61 74 20 61 6e 79 20 74 69 6d 65 2e
            20 49 74 20 69 73 20 69 6e 61 70 70 72 6f 70 72
            69 61 74 65 20 74 6f 20 75 73 65 20 49 6e 74 65
            72 6e 65 74 2d 44 72 61 66 74 73 20 61 73 20 72
            65 66 65 72 65 6e 63 65 20 6d 61 74 65 72 69 61
            6c 20 6f 72 20 74 6f 20 63 69 74 65 20 74 68 65
            6d 20 6f 74 68 65 72 20 74 68 61 6e 20 61 73 20
            2f e2 80 9c 77 6f 72 6b 20 69 6e 20 70 72 6f 67
            72 65 73 73 2e 2f e2 80 9d
        ''')
        expected_tag = hex_to_bytes('eead9d67890cbb22392336fea1851f38')

        self.assertEqual(plaintext, expected_plaintext)
        self.assertEqual(tag, expected_tag)


class TestHKDF(unittest.TestCase):
    def test_gen_key_and_iv(self):
        key, iv = hkdf.gen_key_and_iv(b"secret")
        self.assertEqual(
            key,
            hex_to_bytes("e28fac577f7cbf78dd5340290aae9bfe1a409dddea52a5d32a14e259bbfc22c5")
        )
        self.assertEqual(iv, hex_to_bytes("6e5cca6a1f741ab6b6751c93"))


class TestHttps(unittest.TestCase):
    hostname = "enabled.tls13.com"
    port = 443

    def create_connection(self):
        try:
            import usocket
            sock = usocket.socket()
            sock.connect(usocket.getaddrinfo(self.hostname, self.port)[0][-1])
        except ImportError:
            import socket
            sock = socket.create_connection((self.hostname, self.port))
        return sock

    def assertHttp200(self, s):
        self.assertEqual(s.split("\r\n")[0], "HTTP/1.1 200 OK")

    def _http_get(self, ssock, path):
        ssock.send("GET {} HTTP/1.1\r\nHost:{}\r\n\r\n".format(path, self.hostname).encode())

    def test_https_get(self):
        sock = self.create_connection()
        ssock = tinytls.wrap_socket(sock)
        self._http_get(ssock, "/")
        response = ssock.recv(20).decode()
        self.assertEqual(len(response), 20)
        self.assertHttp200(response)
        sock.close()

    def test_default_context(self):
        sock = self.create_connection()
        context = tinytls.create_default_context()
        ssock = context.wrap_socket(sock)
        self._http_get(ssock, "/")
        self.assertHttp200(ssock.recv(4096).decode())
        sock.close()


if __name__ == "__main__":
    unittest.main()
