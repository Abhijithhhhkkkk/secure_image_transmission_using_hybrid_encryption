import os
import time
import socket
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ascon import encrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# CONFIG
# ----------------------------
WATCH_FOLDER = Path(r"C:\Users\abhijith\secure_image_transmission_using_hybrid_encryption\sender\img")
PUBLIC_KEY_PATH = Path(r"C:\Users\abhijith\secure_image_transmission_using_hybrid_encryption\sender\new_public.pem")

HOST = os.getenv("RECEIVER_IP", "192.168.1.73")
PORT = 5000

SOCKET_TIMEOUT = 10
READY_TIMEOUT = 20
READY_STABLE_CHECKS = 4
READY_SLEEP = 0.3

VALID_EXTENSIONS = {".jpg", ".jpeg", ".png"}
AAD = b"MEDIMGv1"

sent_files = set()

# ----------------------------
# LOAD PUBLIC KEY
# ----------------------------
with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())


def sanitize_name(name: str) -> str:
    allowed = []
    for ch in name.strip():
        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)
    cleaned = "".join(allowed).strip()
    return cleaned if cleaned else "unknown_patient"


def wait_until_file_ready(path: Path, timeout=READY_TIMEOUT) -> bool:
    stable = 0
    last_size = -1
    start = time.time()

    while time.time() - start < timeout:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            time.sleep(0.2)
            continue

        if size > 0 and size == last_size:
            stable += 1
            if stable >= READY_STABLE_CHECKS:
                return True
        else:
            stable = 0

        last_size = size
        time.sleep(READY_SLEEP)

    return False


def get_patient_name(image_path: Path) -> str:
    return sanitize_name(image_path.parent.name)


def build_secure_payload(patient_name: str, filename: str, image_bytes: bytes) -> bytes:
    patient_name_b = patient_name.encode("utf-8", errors="replace")
    filename_b = filename.encode("utf-8", errors="replace")
    print(f"no.of bytes in patient name: {len(patient_name_b)}")
    print(f"no.of bytes in filename: {len(filename_b)}")

    if len(patient_name_b) > 255:
        patient_name_b = patient_name_b[:255]

    if len(filename_b) > 500:
        filename_b = filename_b[:500]

    return (
        len(patient_name_b).to_bytes(2, "big")
        + patient_name_b
        + len(filename_b).to_bytes(2, "big")
        + filename_b
        + image_bytes
    )


def send_image(path: Path) -> None:
    patient_name = get_patient_name(path)
    image_bytes = path.read_bytes()

    ascon_key = os.urandom(16)
    nonce = os.urandom(16)
    print(f"Preparing to send: {path.name} (Patient: {patient_name}, Size: {len(image_bytes)} bytes)");

    secure_payload = build_secure_payload(patient_name, path.name, image_bytes)
    print(f"Secure payload size: {len(secure_payload)} bytes")
    print(f"Encrypting with ASCON...:{ascon_key}")
    print(f"Nonce: {nonce}")
    
    ciphertext = encrypt(ascon_key, nonce, AAD, secure_payload)

    rsa_ct = public_key.encrypt(
        ascon_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    packet = (
        len(rsa_ct).to_bytes(2, "big")
        + rsa_ct
        + nonce
        + ciphertext
    )

    with socket.create_connection((HOST, PORT), timeout=SOCKET_TIMEOUT) as client:
        client.sendall(len(packet).to_bytes(8, "big"))
        client.sendall(packet)


class Handler(FileSystemEventHandler):
    def process_image(self, path: Path):
        if path in sent_files:
            return

        if not path.is_file():
            return

        if path.name.startswith("."):
            return

        if path.suffix.lower() not in VALID_EXTENSIONS:
            return

        if path.parent == WATCH_FOLDER:
            print(f"Skipping file not inside patient folder: {path}")
            return

        print(f"New image detected: {path}")

        if not wait_until_file_ready(path):
            print(f"File not ready, skipping: {path}")
            return

        try:
            send_image(path)
            sent_files.add(path)
            print(f"Sent successfully: {path.name}")
        except Exception as e:
            print(f"Send failed for {path}: {e}")

    def on_created(self, event):
        if event.is_directory:
            return
        self.process_image(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        self.process_image(Path(event.dest_path))


def scan_existing_files():
    for path in WATCH_FOLDER.rglob("*"):
        if path.is_file() and path.suffix.lower() in VALID_EXTENSIONS:
            if path.parent != WATCH_FOLDER and path not in sent_files:
                try:
                    if wait_until_file_ready(path, timeout=3):
                        send_image(path)
                        sent_files.add(path)
                        print(f"Startup sent: {path}")
                except Exception as e:
                    print(f"Startup send failed for {path}: {e}")


def main():
    WATCH_FOLDER.mkdir(parents=True, exist_ok=True)

    print(f"Watching folder: {WATCH_FOLDER}")
    print(f"Sending to: {HOST}:{PORT}")
    print(f"Using public key: {PUBLIC_KEY_PATH}")

    scan_existing_files()

    observer = Observer()
    observer.schedule(Handler(), str(WATCH_FOLDER), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    main()
