import argparse
import json
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "legacy_server"))

from protocol import recv_frame, send_frame

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def fetch(record_id, host="127.0.0.1", port=9100, client_id="client-m1"):
    with socket.create_connection((host, port)) as s:
        hello = recv_frame(s)
        priv = X25519PrivateKey.generate()
        send_frame(s, {"type": "key", "client_id": client_id,
                       "pub": priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()})
        shared = priv.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(hello["pub"])))
        aes = AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                          info=b"standin-gateway").derive(shared))

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
    parser = argparse.ArgumentParser()
    parser.add_argument("record_id", nargs="?", type=int, default=1)
    parser.add_argument(
        "--range",
        dest="record_range",
        nargs=2,
        type=int,
        metavar=("START", "END"),
        help="fetch each record ID in the inclusive range",
    )
    args = parser.parse_args()

    record_ids = (
        range(args.record_range[0], args.record_range[1] + 1)
        if args.record_range
        else [args.record_id]
    )
    for record_id in record_ids:
        print(fetch(record_id))
