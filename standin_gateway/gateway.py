# same message format as the legacy server
import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "legacy_server"))

from protocol import recv_frame, send_frame

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

BASE = Path(__file__).parent

HOST = "127.0.0.1"  # local only
PORT = 9100
CAPTURES = BASE.parent / "captures_gateway"
NOTES = BASE / "connection_notes.jsonl"
CAPTURES.mkdir(exist_ok=True)

RECORDS = {r["id"]: r for r in json.loads(
    (BASE.parent / "legacy_server" / "records.json").read_text())}

lock = threading.Lock()
counter = max(
    (
        int(path.stem[len("session_"):])
        for path in CAPTURES.glob("session_*.json")
        if path.stem[len("session_"):].isdigit()
    ),
    default=0,
)


def raw(pub):
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"standin-gateway").derive(shared)


def save_capture(frames):
    global counter
    with lock:
        counter += 1
        name = f"session_{counter:03d}.json"
        (CAPTURES / name).write_text(json.dumps(frames, indent=2))
    return name


def write_note(client_id, status, capture_file):
    # EDIT to match the connection note format agreed with A and D
    note = {
        "time": datetime.now(timezone.utc).isoformat(),
        "client_id": client_id,
        "tls_version": "standin",
        "cipher_suite": "X25519+AES256GCM",
        "key_groups_offered": ["x25519"],
        "key_group_chosen": "x25519",
        "strong_or_weak": "strong",
        "status": status,
        "capture_file": capture_file,
    }
    with lock:
        with open(NOTES, "a") as f:
            f.write(json.dumps(note) + "\n")


def handle(conn):
    frames = []
    client_id = "unknown"
    status = "ok"

    def send(obj):
        frames.append({"dir": "server->client", "frame": obj})
        send_frame(conn, obj)

    def recv():
        obj = recv_frame(conn)
        frames.append({"dir": "client->server", "frame": obj})
        return obj

    try:
        priv = X25519PrivateKey.generate()
        send({"type": "hello", "kex": "x25519-standin",
             "pub": raw(priv.public_key()).hex()})

        key_msg = recv()
        client_id = key_msg.get("client_id", "unknown")
        shared = priv.exchange(X25519PublicKey.from_public_bytes(
            bytes.fromhex(key_msg["pub"])))
        aes = AESGCM(derive_key(shared))

        req = recv()
        plain = aes.decrypt(bytes.fromhex(
            req["nonce"]), bytes.fromhex(req["ct"]), None)
        record = RECORDS.get(json.loads(plain)["record_id"], {
                             "error": "not found"})

        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, json.dumps(record).encode(), None)
        send({"type": "data", "nonce": nonce.hex(), "ct": ct.hex()})
    except Exception as ex:
        status = f"error: {ex}"
    finally:
        conn.close()
        write_note(client_id, status, save_capture(frames))


def main():
    print(f"STAND-IN gateway on {HOST}:{PORT} (X25519 only, NOT quantum-safe)")
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
