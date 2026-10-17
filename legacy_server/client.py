import json
import os
import socket
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import toy_rsa
from protocol import recv_frame, send_frame


def fetch(record_id, host="127.0.0.1", port=9000, client_id="client-1"):
    with socket.create_connection((host, port)) as s:
        hello = recv_frame(s)
        public = (hello["n"], hello["e"])

        secret = toy_rsa.new_secret()
        send_frame(s, {
            "type": "key",
            "client_id": client_id,
            "locked_secret": toy_rsa.encrypt(secret, public),
        })
        aes = AESGCM(toy_rsa.derive_aes_key(secret))

        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, json.dumps(
            {"record_id": record_id}).encode(), None)
        send_frame(
            s, {"type": "request", "nonce": nonce.hex(), "ct": ct.hex()})

        reply = recv_frame(s)
        plain = aes.decrypt(bytes.fromhex(
            reply["nonce"]), bytes.fromhex(reply["ct"]), None)
        return json.loads(plain)


if __name__ == "__main__":
    rid = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    print(fetch(rid))
