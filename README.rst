---------------
tinytls
---------------

tinytls is a pure python TLS1.3 protocol wrapper.

As a result of learning TLS1.3, 
I wrote this as a sample implementation of TLS1.3 client.

Builtin ssl module (CPython3.7+, OpenSSL1.1.1+) can use as TLS1.3 client,
so there is no advantage to use it especially in Python 3.

Restriction
+++++++++++++++

- Available TLS1.3 only, not TLS1.2 or under.
- Support TLS_CHACHA20_POLY1305_SHA256 cipher suite only.
- Support secp256r1 (P-256), secp384r1 (P-384), and X25519 key exchanges.
- It does not verify TLS certificate.
- Not support `0-RTT`
- Client certificate authentication is not available.

Supported Python
+++++++++++++++++++

- Python3.11+
- MicroPython

Example
++++++++

CPython
::

   import socket
   import tinytls

   hostname = "enabled.tls13.com"

   sock = socket.create_connection((hostname, 443))
   with tinytls.wrap_socket(sock) as ssock:
       ssock.send("GET / HTTP/1.1\r\nHost:{}\r\n\r\n".format(hostname).encode())
       print(ssock.recv(4096).decode())

MicroPython
::

   import usocket
   import tinytls

   hostname = "enabled.tls13.com"

   sock = usocket.socket()
   sock.connect(usocket.getaddrinfo(hostname, 443)[0][-1])

   with tinytls.wrap_socket(sock) as ssock:
       ssock.send("GET / HTTP/1.1\r\nHost:{}\r\n\r\n".format(hostname).encode())
       print(ssock.recv(4096).decode())

Reference
++++++++++++++++++++

- https://github.com/tex2e/mako-tls13 (special thanks!)
- https://datatracker.ietf.org/doc/html/rfc8446
- https://datatracker.ietf.org/doc/html/rfc5903
- https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant
- https://asecuritysite.com/encryption/python_25519ecdh
- https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

Check the server
+++++++++++++++++++++++++++++

If you cannot connect to the server with tinytls,
use a command like the following to check if the server can be connected

::

   openssl s_client -tls1_3 -ciphersuites 'TLS_CHACHA20_POLY1305_SHA256' \
                                -curves 'prime256v1:secp384r1:X25519' \
                                -state -debug -connect enabled.tls13.com:443
