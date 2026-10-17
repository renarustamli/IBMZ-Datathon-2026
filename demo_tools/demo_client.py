"""Bank client for the demo: fetches records over C's legacy protocol, optionally inside TLS.

  python demo_client.py HOST:PORT [--tls] [--count N] [--client-prefix NAME]

Reuses legacy_server/client.py unchanged; --tls only wraps its socket, the way a client
talking to the gateway would. The client id goes in the TLS server name (SNI), which is
where the gateway reads it from (gateway/README.md).
"""
import argparse
import os
import socket
import ssl
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "legacy_server"))
import client  # noqa: E402  (C's client)


def tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # the client id is sent as SNI, so it never matches the cert name
    ca = os.environ.get("GATEWAY_CA")
    if ca:
        ctx.load_verify_locations(ca)
    else:
        ctx.verify_mode = ssl.CERT_NONE  # demo only: the gateway cert is self-signed
    return ctx


class _TLSSocketModule:
    """Stands in for the `socket` module inside client.py so its connections go over TLS."""
    def __init__(self, ctx):
        self.ctx, self.sni, self.last = ctx, None, None

    def create_connection(self, addr, *a, **kw):
        s = self.ctx.wrap_socket(socket.create_connection(addr, *a, **kw), server_hostname=self.sni)
        group = getattr(s, "group", lambda: None)()  # Python 3.15+ reports the key exchange group
        self.last = f"  over {s.version()}, {s.cipher()[0]}" + (f", {group}" if group else "")
        return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("addr")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--client-prefix", default="branch")
    args = ap.parse_args()
    host, port = args.addr.rsplit(":", 1)

    shim = None
    if args.tls:
        shim = _TLSSocketModule(tls_context())
        client.socket = shim
    for i in range(args.count):
        rid = i % 20 + 1
        cid = f"{args.client_prefix}-{i % 3 + 1}"
        if shim:
            shim.sni = cid
        rec = client.fetch(rid, host=host, port=int(port), client_id=cid)
        print(f"  [client] record {rid}: {rec.get('name')} (account {rec.get('account_number')})"
              + (shim.last if shim else ""), flush=True)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
