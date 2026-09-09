import hashlib
import hmac
import json
import os
import socket
import ssl
import struct
from pathlib import Path

HOST = "localhost"
PORT = 8443

CERT_FILE = "certs/server.crt"
KEY_FILE = "certs/server.key"
CA_FILE = "certs/ca.crt"

UPLOAD_DIR = Path("uploads")
MAX_FILE_SIZE = 1024 * 1024 * 1024
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

    if len(payload) > 1024 * 1024:
        raise ValueError("Control message is too large")

    sock.sendall(struct.pack("!I", len(payload)))
    sock.sendall(payload)

def safe_filename(name):
    if not isinstance(name, str):
        raise ValueError("Invalid filename")

    if not name or len(name) > 255:
        raise ValueError("Invalid filename")

    path = Path(name)

    if path.name != name:
        raise ValueError("Path components are not allowed")

    if name in {".", ".."}:
        raise ValueError("Invalid filename")

    if "\x00" in name:
        raise ValueError("Invalid filename")

    return name

def receive_file(sock, metadata):
    filename = safe_filename(metadata["filename"])
    file_size = metadata["size"]
    expected_hash = metadata["sha256"].lower()

    if not isinstance(file_size, int):
        raise ValueError("Invalid file size")

    if file_size < 0 or file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds configured size limit")

    if not isinstance(expected_hash, str) or len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
        raise ValueError("Invalid SHA-256 digest")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    destination = UPLOAD_DIR / filename
    temporary = UPLOAD_DIR / f".{filename}.part"

    if destination.exists():
        raise FileExistsError("File already exists")

    hasher = hashlib.sha256()
    remaining = file_size

    try:
        with open(temporary, "xb") as output:
            while remaining:
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = recv_exact(sock, chunk_size)

                output.write(chunk)
                hasher.update(chunk)

                remaining -= len(chunk)

            output.flush()
            os.fsync(output.fileno())

        actual_hash = hasher.hexdigest()

        if not hmac.compare_digest(actual_hash, expected_hash):
            temporary.unlink(missing_ok=True)
            raise ValueError(f"SHA-256 mismatch: expected {expected_hash}, got {actual_hash}")

        os.replace(temporary, destination)
        send_message(sock, {"status": "ok", "filename": filename, "sha256": actual_hash})
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

def handle_client(conn, address):
    print(f"Client connected: {address}")

    try:
        peer_cert = conn.getpeercert()

        if not peer_cert:
            raise ssl.SSLError("Client certificate missing")

        print("Client certificate accepted")

        request = recv_message(conn)

        if request.get("operation") != "upload":
            raise ValueError("Unsupported operation")

        receive_file(conn, request)

        print(f"Upload completed: {request['filename']}")
    except Exception as e:
        print(f"Client error: {e}")

        try:
            send_message(conn, {"status": "error", "error": str(e)})
        except Exception:
            pass
    finally:
        conn.close()
        print(f"Client disconnected: {address}")

def create_tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(CA_FILE)

    context.check_hostname = False

    return context

def main():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    tls_context = create_tls_context()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(20)

        print(f"Secure file server listening on {HOST}:{PORT}")

        with tls_context.wrap_socket(server, server_side=True) as tls_server:
            while True:
                conn, address = tls_server.accept()
                handle_client(conn, address)

if __name__ == "__main__":
    main()
