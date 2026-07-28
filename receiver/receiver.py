import os
import time
import socket
from pathlib import Path

from ascon import decrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# CONFIG
# ----------------------------
HOST = "0.0.0.0"
PORT = 5000
AAD = b"MEDIMGv1"

PRIVATE_KEY_PATH = "new_private.pem"
SAVE_DIR = Path(r"C:\Users\abhijith\secure_image_transmission_using_hybrid_encryption\receiver\static\images")
SAVE_DIR.mkdir(parents=True, exist_ok=True)


def sanitize_name(name: str) -> str:
    allowed = []
    for ch in name.strip():
        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)
    cleaned = "".join(allowed).strip()
    return cleaned if cleaned else "unknown_patient"


def recv_exact(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        print(f"Received chunk: {len(chunk)} bytes")
        if not chunk:
            raise ConnectionError("Connection closed early")
        data += chunk
    return data


def parse_secure_payload(payload: bytes):
    """
    Payload format:
    [2 bytes patient_name_len]
    [patient_name bytes]
    [2 bytes filename_len]
    [filename bytes]
    [image bytes]
    """
    print(f"Parsing secure payload of size: {len(payload)} bytes")
    offset = 0

    if len(payload) < 2:
        raise ValueError("Payload too short")

    patient_len = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2

    if len(payload) < offset + patient_len + 2:
        raise ValueError("Invalid patient name field")

    patient_name = payload[offset:offset + patient_len].decode("utf-8", errors="replace")
    offset += patient_len

    filename_len = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2

    if len(payload) < offset + filename_len:
        raise ValueError("Invalid filename field")

    filename = payload[offset:offset + filename_len].decode("utf-8", errors="replace")
    offset += filename_len

    image_bytes = payload[offset:]
    if not image_bytes:
        raise ValueError("No image bytes found")

    return patient_name, filename, image_bytes


with open(PRIVATE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)

print(f"Receiver listening on {HOST}:{PORT}")
print(f"Saving decrypted images to: {SAVE_DIR}")

while True:
    conn, addr = server.accept()
    print("Connection request from:", addr)

    choice = input("Accept connection? (yes/no): ").strip().lower()

    if choice not in ("yes", "y"):
        print("Connection rejected.")
        conn.sendall(b"REJECT")
        conn.close()
        continue

    conn.sendall(b"ACCEPT")
    print("Connection accepted.")

    

    try:
        total_size = int.from_bytes(recv_exact(conn, 8), "big")
        packet = recv_exact(conn, total_size)

        rsa_len = int.from_bytes(packet[:2], "big")
        offset = 2

        rsa_ct = packet[offset:offset + rsa_len]
        offset += rsa_len

        nonce = packet[offset:offset + 16]
        offset += 16

        ciphertext = packet[offset:]

        if len(nonce) != 16:
            raise ValueError("Invalid nonce length")

        session_key = private_key.decrypt(
            rsa_ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        print(f"Decrypted session key: {session_key}")

        plaintext = decrypt(session_key, nonce, AAD, ciphertext)

        if plaintext is None:
            print("Authentication failed")
            continue

        patient_name, original_filename, image_bytes = parse_secure_payload(plaintext)
        patient_name = sanitize_name(patient_name)

        patient_folder = SAVE_DIR / patient_name
        patient_folder.mkdir(parents=True, exist_ok=True)

        ext = Path(original_filename).suffix.lower()
        if ext not in [".jpg", ".jpeg", ".png"]:
            ext = ".jpg"

        save_name = f"{int(time.time())}_{Path(original_filename).stem}{ext}"
        save_path = patient_folder / save_name

        with open(save_path, "wb") as f:
            f.write(image_bytes)

        print(f"Saved: {save_path}")

    except Exception as e:
        print("Error:", e)

    finally:
        conn.close()