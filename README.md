# CipherLink

A Python-based secure file transfer application demonstrating encrypted client-server communication, mutual TLS authentication, file integrity verification, and defensive input handling.

This project was built as a portfolio project to demonstrate practical skills in **Python, networking, cybersecurity fundamentals, secure communications, and file handling**.

## Features

* **TLS 1.3 encrypted communication**
* **Mutual TLS (mTLS)** authentication using client and server certificates
* **Certificate-based client authentication**
* **SHA-256 file integrity verification**
* **Chunked file transfer** for efficient handling of large files
* **Configurable file size limit** (1 GB by default)
* **Safe filename validation** to prevent path traversal
* **Length-prefixed JSON control messages**
* **Temporary file handling** during uploads
* **Atomic file replacement** after successful integrity verification
* **Existing-file protection** to prevent accidental overwrites
* **Socket connection timeout** on the client
* **Cleanup of incomplete uploads** after errors
* **Client-side upload progress display**
* Structured error responses between client and server

## How It Works

The application consists of two components:

**Client**

1. Validates the requested file.
2. Calculates its SHA-256 digest.
3. Establishes a TLS 1.3 connection to the server.
4. Authenticates using a client certificate.
5. Sends upload metadata to the server.
6. Transfers the file in chunks.
7. Verifies the server's returned SHA-256 digest.

**Server**

1. Listens for incoming TCP connections.
2. Establishes TLS 1.3 connections.
3. Requires and validates a client certificate.
4. Validates the upload request and file metadata.
5. Receives the file in chunks.
6. Calculates the SHA-256 digest while receiving the file.
7. Verifies the received digest against the client's expected digest.
8. Moves the completed temporary file into the upload directory only after successful verification.

### High-Level Flow

```text
Client                         Server
  │                              │
  │──── TLS 1.3 + mTLS ─────────>│
  │                              │
  │──── Upload metadata ────────>│
  │                              │
  │──── File chunks ────────────>│
  │                              │
  │                         SHA-256 verification
  │                              │
  │<──── Success + digest ───────│
  │                              │
```

## Security Considerations

The project demonstrates several security-focused design principles:

* **Encryption in transit:** TLS protects file contents and protocol traffic.
* **Mutual authentication:** Both sides participate in certificate-based authentication.
* **Modern TLS:** TLS 1.3 is enforced rather than allowing older protocol versions.
* **Integrity checking:** SHA-256 is calculated independently by the client and server.
* **Constant-time digest comparison:** `hmac.compare_digest()` is used for digest verification.
* **Path traversal protection:** Filenames are restricted to simple filenames rather than arbitrary paths.
* **Resource limits:** Control messages and uploaded files have configurable size limits.
* **Safe upload handling:** Files are initially written to temporary `.part` files and only committed after successful verification.
* **No accidental overwrites:** Existing destination files are rejected.
* **Incomplete upload cleanup:** Temporary files are removed when an upload fails.

## Skills Demonstrated

### Python

* Socket programming
* File I/O
* Exception handling
* JSON serialization
* `pathlib` filesystem operations
* Cryptographic hashing
* SSL/TLS APIs
* Command-line argument handling
* Modular function design

### Networking

* TCP client-server communication
* Socket lifecycle management
* Application-layer message framing
* Length-prefixed protocols
* Connection handling
* Client/server request-response communication

### Cybersecurity

* TLS 1.3
* Mutual TLS (mTLS)
* X.509 certificate authentication
* Encryption in transit
* File integrity verification
* Secure filename validation
* Path traversal prevention
* Input validation
* Resource limiting
* Secure temporary-file handling

### Systems / IT

* Secure service configuration
* Client-server architecture
* Filesystem permissions and handling
* Error handling and recovery
* Network service troubleshooting
* Defensive programming

## Project Structure

```text
.
├── client.py
├── server.py
├── certs/
│   ├── ca.crt
│   ├── client.crt
│   ├── client.key
│   ├── server.crt
│   └── server.key
└── uploads/
```

> Certificate and private-key files should be generated and managed separately and should **not** be committed to a public repository.

## Configuration

The application currently uses:

| Setting               | Default     |
| --------------------- | ----------- |
| Server host           | `localhost` |
| Server port           | `8443`      |
| TLS version           | TLS 1.3     |
| Upload directory      | `uploads/`  |
| Maximum file size     | 1 GB        |
| Transfer chunk size   | 64 KB       |
| Control message limit | 1 MB        |

These values are defined directly in the client and server configuration sections.

## Running the Application

Start the server:

```bash
python server.py
```

Upload a file from the client:

```bash
python client.py path/to/file
```

The client displays the file size, SHA-256 digest, TLS version/cipher information, and upload progress.

## Limitations / Future Improvements

This project intentionally focuses on demonstrating secure file-transfer fundamentals rather than being a production-ready file transfer service.

Potential future improvements include:

* Concurrent client handling
* Authentication/authorization beyond certificate identity
* Configurable host, port, and upload limits
* Structured logging
* Rate limiting
* Improved certificate identity validation
* Download functionality
* Resume support for interrupted transfers
* Automated tests
* Configuration through environment variables or a configuration file
* Deployment as a managed service
* Additional monitoring and audit logging

## Technologies

* **Python 3**
* `socket`
* `ssl`
* `hashlib`
* `hmac`
* `json`
* `struct`
* `pathlib`

## Purpose

This project was created to demonstrate practical understanding of **secure networking and systems programming** in Python, with particular focus on TLS, authentication, data integrity, input validation, and reliable file handling.
