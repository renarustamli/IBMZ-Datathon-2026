"""The eavesdropper: a TCP relay that records every byte passing through it.

  python wiretap.py LISTEN_PORT TARGET_HOST:TARGET_PORT OUT_DIR

Each connection is saved as OUT_DIR/session_NNN.json in the same frame format
attacker/attack.py reads. Bytes that parse as the legacy protocol (length-prefixed
JSON) are saved as readable frames; anything else (e.g. TLS) is saved as opaque bytes,
which is all a real eavesdropper would have.
"""
import json
import socket
import struct
import sys
import threading
from pathlib import Path

lock = threading.Lock()


def parse_frames(data, direction):
    """Split a recorded byte stream into legacy-protocol frames, or one opaque blob."""
    frames, i = [], 0
    while i + 4 <= len(data):
        (n,) = struct.unpack(">I", data[i:i + 4])
        try:
            obj = json.loads(data[i + 4:i + 4 + n])
        except ValueError:
            break
        if not isinstance(obj, dict) or i + 4 + n > len(data):
            break
        frames.append({"dir": direction, "frame": obj})
        i += 4 + n
    if i < len(data):
        rest = data[i:]
        kind = "tls" if rest[:1] in (b"\x16", b"\x17") and rest[1:2] == b"\x03" else "unknown"
        frames.append({"dir": direction, "frame": {
            "type": "opaque", "looks_like": kind, "bytes": len(rest), "preview_hex": rest[:24].hex()}})
    return frames


def pump(src, dst, buf):
    try:
        while chunk := src.recv(65536):
            buf.extend(chunk)
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client, target, out_dir, counter):
    up, down = bytearray(), bytearray()
    try:
        server = socket.create_connection(target)
    except OSError as e:
        print(f"  [wiretap] cannot reach {target[0]}:{target[1]}: {e}", flush=True)
        client.close()
        return
    t = threading.Thread(target=pump, args=(server, client, down), daemon=True)
    t.start()
    pump(client, server, up)
    t.join(timeout=10)
    client.close()
    server.close()
    if not up:  # a port check, not a client session
        return

    frames = parse_frames(bytes(down), "server->client") + parse_frames(bytes(up), "client->server")
    with lock:
        counter[0] += 1
        name = f"session_{counter[0]:03d}.json"
    (out_dir / name).write_text(json.dumps(frames, indent=2))
    opaque = [f["frame"] for f in frames if f["frame"].get("type") == "opaque"]
    what = ("encrypted TLS, unreadable" if any(o["looks_like"] == "tls" for o in opaque)
            else "unreadable bytes" if opaque else "readable legacy protocol")
    print(f"  [wiretap] recorded {name}: {len(up) + len(down)} bytes ({what})", flush=True)


def main():
    port = int(sys.argv[1])
    host, tport = sys.argv[2].rsplit(":", 1)
    out_dir = Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    counter = [len(list(out_dir.glob("session_*.json")))]
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen()
        print(f"  [wiretap] listening on :{port} -> {host}:{tport}", flush=True)
        while True:
            c, _ = srv.accept()
            threading.Thread(target=handle, args=(c, (host, int(tport)), out_dir, counter), daemon=True).start()


if __name__ == "__main__":
    main()
