import json
import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import toy_rsa
from protocol import recv_frame, send_frame

HOST = "127.0.0.1"  # local only. Change to "0.0.0.0" only when demoing across machines
PORT = 9000

BASE = Path(__file__).parent
CAPTURES = BASE.parent / "captures"
NOTES = BASE / "connection_notes.jsonl"
CAPTURES.mkdir(exist_ok=True)

RECORDS = {r["id"]: r for r in json.loads((BASE / "records.json").read_text())}
PUBLIC, PRIVATE = toy_rsa.generate_keypair()

lock = threading.Lock()
counter = len(list(CAPTURES.glob("session_*.json")))


def save_capture(frames):
    """Save exactly what went over the wire. The attacker will only ever read these files."""
    global counter
    with lock:
        counter += 1
        name = f"session_{counter:03d}.json"
        (CAPTURES / name).write_text(json.dumps(frames, indent=2))
    return name


def write_note(client_id, status, capture_file):
    # EDIT these fields to match the connection note format you agreed with A and D
    note = {
        "time": datetime.now(timezone.utc).isoformat(),
        "client_id": client_id,
        "tls_version": "toy-legacy",
        "cipher_suite": "TOY-RSA64+AES256GCM",
        "key_groups_offered": ["toy-rsa-64"],
        "key_group_chosen": "toy-rsa-64",
        "strong_or_weak": "weak",
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
        send({"type": "hello", "n": PUBLIC[0], "e": PUBLIC[1]})

        key_msg = recv()
        client_id = key_msg.get("client_id", "unknown")
        secret = toy_rsa.decrypt(key_msg["locked_secret"], PRIVATE)
        aes = AESGCM(toy_rsa.derive_aes_key(secret))

        req = recv()
        plain = aes.decrypt(bytes.fromhex(
            req["nonce"]), bytes.fromhex(req["ct"]), None)
        record_id = json.loads(plain)["record_id"]
        record = RECORDS.get(record_id, {"error": "not found"})

        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, json.dumps(record).encode(), None)
        send({"type": "data", "nonce": nonce.hex(), "ct": ct.hex()})
    except Exception as ex:
        status = f"error: {ex}"
    finally:
        conn.close()
        write_note(client_id, status, save_capture(frames))


def main():
    print(
        f"Legacy server on {HOST}:{PORT}. Toy key n has {PUBLIC[0].bit_length()} bits")
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
