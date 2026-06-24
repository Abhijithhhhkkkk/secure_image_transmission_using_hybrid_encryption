# Medical Image Receiver System

## Project Overview

The Medical Image Receiver System is a small, secure platform for transferring medical images from a Raspberry Pi (sender) to a laptop/computer (receiver) on a local network. The system uses a hybrid encryption scheme (ASCON for payload encryption and RSA to protect the session key) so that patient-identifying information and image data are protected during transit.

Core goals:
- Confidential transfer of patient images between devices on a trusted network.
- Simple, patient-wise organization of received images on the receiver machine.
- Minimal setup so it can run on low-power hardware (Raspberry Pi).

---

## Key Features

- Watches a configured directory on the sender for new images organized by patient name.
- Packages patient metadata and image bytes into a single data packet.
- Encrypts the packet with ASCON using a one-time session key.
- Encrypts the ASCON session key with the receiver's RSA public key (hybrid encryption).
- Sends the encrypted packet over a TCP socket to the receiver.
- Receiver decrypts the session key with its RSA private key, decrypts the packet, and stores the image in a patient-specific folder with a timestamped filename.

---

## How It Works (high level)

1) Patient image storage on Raspberry Pi
- Sender directory layout should be: /home/pi/sender/img/<PatientName>/<image-files>
- Each folder name is treated as the patient identifier.

Example:

```text
/home/pi/sender/img/
├── Rahul/
│   ├── image1.jpg
│   └── image2.png
├── Anjali/
│   └── scan1.jpg
```

2) Image detection & encryption
- A file-watcher (inotify or polling) detects newly added image files.
- When a new file is detected, the sender builds a data packet containing:
  - patient name (from folder name)
  - filename and timestamp
  - mime type and optional metadata
  - raw image bytes (or a compressed representation)
- The packet is encrypted using ASCON with a randomly generated session key.
- The session key is encrypted using the receiver's RSA public key and attached to the packet.

3) Secure transfer to receiver
- The sender connects to the receiver's configured host and TCP port and sends the encrypted packet.
- The receiver listens for incoming connections, validates incoming packets, and acknowledges receipt.
- Optional: add TLS for socket transport or implement application-level integrity checks (HMAC or authenticated encryption — ASCON already provides AEAD semantics for the payload).

4) Saving and organizing images on receiver
- The receiver uses its RSA private key to decrypt the ASCON session key.
- Using the recovered session key, the receiver decrypts the payload and extracts the patient name and image bytes.
- The receiver ensures a directory exists for the patient (e.g., ./images/<PatientName>/) and saves the image using a timestamped filename to avoid overwrites.

---

## Requirements

- Raspberry Pi or Linux sender (Python 3.8+ recommended)
- Receiver machine (Linux/macOS/Windows) with Python 3.8+
- Python dependencies: ascon implementation, pycryptodome or cryptography for RSA operations, watchdog (or other file-watcher), and any socket/networking libraries used by the implementation.
- RSA keypair generated for the receiver (public key accessible by the sender).

---

## Setup (example)

1. Generate RSA keypair on the receiver and copy the public key to the sender:

`

2. Configure sender settings (host, port, path to receiver_public.pem, image directory).
3. Configure receiver settings (listening port, path to receiver_private.pem, storage directory).

---

## Running (example)

- Start the receiver first so it is listening for connections.
- Start the sender/watcher on the Raspberry Pi. When a new image is placed in /home/pi/sender/img/<PatientName>/, the watcher packages, encrypts, and transmits the file.

---

## Security notes and best practices

- Keep the receiver private key secret and protected (file permissions, secure storage).
- Use sufficiently strong RSA key sizes (2048 bits or higher) and rotate keys periodically.
- Consider running the socket over TLS (or a VPN) if network-level security is required beyond local network trust.
- Validate and sanitize patient names before using them as directory names to prevent path traversal or filesystem injection.
- Limit accepted file types and scan images for malware if running in untrusted environments.

---

