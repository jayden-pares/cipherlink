import hashlib
import json
import socket
import ssl
import struct
import sys
from pathlib import Path

SERVER_HOST = "localhost"
SERVER_PORT = 8443

CA_FILE = "certs/ca.crt"
CLIENT_CERT = "certs/client.crt"
CLIENT_KEY = "certs/client.key"

CHUNK_SIZE = 64 * 1024

def recv_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")

        data.extend(chunk)

    return bytes(data)

def recv_message(sock):
    raw_length = recv_exact(sock, 4)
    length = struct.unpack("!I", raw_length)[0]

    if length > 1024 * 1024:
        raise ValueError("Control message is too large")

    payload = recv_exact(sock, length)
    return json.loads(payload.decode("utf-8"))

def send_message(sock, message):
    payload = json.dumps(message).encode("utf-8")

    sock.sendall(struct.pack("!I", len(payload)))
    sock.sendall(payload)

def sha256_file(path):
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            hasher.update(chunk)

    return hasher.hexdigest()

def create_tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(CA_FILE)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = True

    return context

def upload(server_host, server_port, filepath):
    filepath = Path(filepath)

    if not filepath.is_file():
        raise FileNotFoundError(filepath)

    file_size = filepath.stat().st_size
    file_hash = sha256_file(filepath)

    print(f"File:   {filepath}")
    print(f"Size:   {file_size:,} bytes")
    print(f"SHA256: {file_hash}")

    tls_context = create_tls_context()

    with socket.create_connection((server_host, server_port), timeout=30) as raw_socket:
        with tls_context.wrap_socket(raw_socket, server_hostname=server_host) as sock:
            print("TLS connection established:", sock.version(), sock.cipher()[0])

            request = {"operation": "upload", "filename": filepath.name, "size": file_size, "sha256": file_hash}

            send_message(sock, request)

            with open(filepath, "rb") as f:
                sent = 0

                while chunk := f.read(CHUNK_SIZE):
                    sock.sendall(chunk)
                    sent += len(chunk)

                    print(f"\rUploaded {sent:,}/{file_size:,} bytes", end="", flush=True)

            print()

            response = recv_message(sock)

            if response.get("status") != "ok":
                raise RuntimeError(response.get("error", "Unknown server error"))

            if response["sha256"] != file_hash:
                raise RuntimeError("Server returned an unexpected SHA-256 digest")

            print("Upload successful.")
            print("Server SHA-256:", response["sha256"])

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} FILE")
        raise SystemExit(2)

    upload(SERVER_HOST, SERVER_PORT, sys.argv[1])

if __name__ == "__main__":
    main()
