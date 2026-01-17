#!/usr/bin/env python3
import argparse
import socket
import ssl
import struct
import sys

DEFAULT_DATA_TEMPLATE = "Server{sid}_Data: [Demo payload from server {sid}]"
SGX_HOST = "127.0.0.1"
SGX_PORT = 12345


def run_server(server_id: int, payload: str) -> None:
    print(f"[DATA_SERVER {server_id}] Connecting to SGX at {SGX_HOST}:{SGX_PORT} (TLS)")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # demo/trust-all; in prod provide CA

    while True:
        try:
            with socket.create_connection((SGX_HOST, SGX_PORT)) as sock:
                with ctx.wrap_socket(sock, server_hostname="sgx-local") as tls:
                    print(f"[DATA_SERVER {server_id}] TLS handshake OK")

                    # Send identification
                    ident = f"SERVER:{server_id}\n".encode()
                    tls.sendall(ident)
                    print(f"[DATA_SERVER {server_id}] Sent ID")

                    # Main loop: read [len][payload], respond with [len][payload]
                    while True:
                        hdr = _read_exact(tls, 4)
                        if hdr is None:
                            print(f"[DATA_SERVER {server_id}] Connection closed while reading size")
                            break
                        (size,) = struct.unpack("<I", hdr)
                        if size == 0 or size > 4096:
                            print(f"[DATA_SERVER {server_id}] Invalid size {size}")
                            break

                        payload_req = _read_exact(tls, size)
                        if payload_req is None:
                            print(f"[DATA_SERVER {server_id}] Connection closed while reading payload")
                            break

                        req_text = payload_req.decode(errors="ignore")
                        print(f"[DATA_SERVER {server_id}] Request: {req_text}")

                        resp_bytes = payload.encode()
                        tls.sendall(struct.pack("<I", len(resp_bytes)) + resp_bytes)
                        print(f"[DATA_SERVER {server_id}] Sent {len(resp_bytes)} bytes")
        except KeyboardInterrupt:
            print(f"\n[DATA_SERVER {server_id}] Stopping (keyboard interrupt)")
            sys.exit(0)
        except Exception as exc:
            print(f"[DATA_SERVER {server_id}] Connection error: {exc}; retrying in 1s")
            try:
                import time

                time.sleep(1)
            except KeyboardInterrupt:
                sys.exit(0)


def _read_exact(sock: ssl.SSLSocket, length: int):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS data server client for SGX demo")
    parser.add_argument("--id", type=int, default=1, help="Server ID")
    parser.add_argument(
        "--data",
        default=None,
        help="Payload to return. If omitted, uses a default message with server id.",
    )
    args = parser.parse_args()

    payload = args.data if args.data is not None else DEFAULT_DATA_TEMPLATE.format(sid=args.id)
    run_server(args.id, payload)


if __name__ == "__main__":
    main()
