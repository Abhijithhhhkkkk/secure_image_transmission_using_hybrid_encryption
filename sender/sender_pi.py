
import os
import time
import socket
import csv
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ascon import encrypt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ----------------------------
# CONFIG
# ----------------------------
WATCH_FOLDER = Path(
    "/home/abhijithk/secure_image_transmission_using_hybrid_encryption/sender/img"
)

PUBLIC_KEY_PATH = Path(
    "/home/abhijithk/secure_image_transmission_using_hybrid_encryption/sender/new_public.pem"
)

HOST = os.getenv("RECEIVER_IP", "192.168.1.76")
PORT = 5000

SOCKET_TIMEOUT = 10
READY_TIMEOUT = 20
READY_STABLE_CHECKS = 4
READY_SLEEP = 0.3

VALID_EXTENSIONS = {".jpg", ".jpeg", ".png"}
AAD = b"MEDIMGv1"

CSV_FILE = "performance_log.csv"

sent_files = set()

# ----------------------------
# CREATE CSV HEADER
# ----------------------------
if not os.path.exists(CSV_FILE):
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "Filename",
            "ImageSizeKB",
            "ASCON_Time",
            "RSA_Time",
            "Total_Encryption_Time",
            "Transmission_Time",
            "Overall_Delay",
            "Throughput_KBps"
        ])

# ----------------------------
# LOAD PUBLIC KEY
# ----------------------------
with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())


# ----------------------------
# SANITIZE PATIENT NAME
# ----------------------------
def sanitize_name(name: str) -> str:
    allowed = []

    for ch in name.strip():
        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)

    cleaned = "".join(allowed).strip()

    return cleaned if cleaned else "unknown_patient"


# ----------------------------
# WAIT UNTIL FILE READY
# ----------------------------
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


# ----------------------------
# GET PATIENT NAME
# ----------------------------
def get_patient_name(image_path: Path) -> str:
    return sanitize_name(image_path.parent.name)


# ----------------------------
# BUILD PAYLOAD
# ----------------------------
def build_secure_payload(
    patient_name: str,
    filename: str,
    image_bytes: bytes
) -> bytes:

    patient_name_b = patient_name.encode(
        "utf-8",
        errors="replace"
    )

    filename_b = filename.encode(
        "utf-8",
        errors="replace"
    )

    print(f"Patient name bytes : {len(patient_name_b)}")
    print(f"Filename bytes     : {len(filename_b)}")

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


# ----------------------------
# SEND IMAGE
# ----------------------------
def send_image(path: Path) -> None:

    patient_name = get_patient_name(path)

    image_bytes = path.read_bytes()

    ascon_key = os.urandom(16)
    nonce = os.urandom(16)

    print("\n========================================")
    print(f"Preparing to send : {path.name}")
    print(f"Patient           : {patient_name}")
    print(f"Image Size        : {len(image_bytes)} bytes")
    print("========================================")

    secure_payload = build_secure_payload(
        patient_name,
        path.name,
        image_bytes
    )

    # -----------------------------------
    # TOTAL PROCESS START
    # -----------------------------------
    total_start = time.perf_counter()

    # -----------------------------------
    # ASCON ENCRYPTION
    # -----------------------------------
    ascon_start = time.perf_counter()

    ciphertext = encrypt(
        ascon_key,
        nonce,
        AAD,
        secure_payload
    )

    ascon_end = time.perf_counter()
    ascon_time = ascon_end - ascon_start

    # -----------------------------------
    # RSA ENCRYPTION
    # -----------------------------------
    rsa_start = time.perf_counter()

    rsa_ct = public_key.encrypt(
        ascon_key,

        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),

            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    rsa_end = time.perf_counter()
    rsa_time = rsa_end - rsa_start

    # -----------------------------------
    # PACKET CREATION
    # -----------------------------------
    packet = (
        len(rsa_ct).to_bytes(2, "big")
        + rsa_ct
        + nonce
        + ciphertext
    )

    encryption_end = time.perf_counter()
    total_encryption_time = encryption_end - total_start

    # -----------------------------------
    # TRANSMISSION TIME
    # -----------------------------------
    transmission_start = time.perf_counter()

    with socket.create_connection(
        (HOST, PORT),
        timeout=SOCKET_TIMEOUT
    ) as client:

        client.sendall(
            len(packet).to_bytes(8, "big")
        )

        client.sendall(packet)

    transmission_end = time.perf_counter()

    transmission_time = (
        transmission_end - transmission_start
    )

    # -----------------------------------
    # OVERALL DELAY
    # -----------------------------------
    overall_delay = (
        transmission_end - total_start
    )

    # -----------------------------------
    # THROUGHPUT
    # -----------------------------------
    image_size_kb = len(image_bytes) / 1024

    throughput = (
        image_size_kb / overall_delay
    )

    # -----------------------------------
    # PRINT PERFORMANCE
    # -----------------------------------
    print("\n========== PERFORMANCE ==========")

    print(f"Image Size            : {image_size_kb:.2f} KB")

    print(
        f"ASCON Encryption Time : "
        f"{ascon_time:.6f} sec"
    )

    print(
        f"RSA Encryption Time   : "
        f"{rsa_time:.6f} sec"
    )

    print(
        f"Total Encryption Time : "
        f"{total_encryption_time:.6f} sec"
    )

    print(
        f"Transmission Time     : "
        f"{transmission_time:.6f} sec"
    )

    print(
        f"Overall Delay         : "
        f"{overall_delay:.6f} sec"
    )

    print(
        f"Throughput            : "
        f"{throughput:.2f} KB/s"
    )

    print("=================================\n")

    # -----------------------------------
    # SAVE TO CSV
    # -----------------------------------
    with open(CSV_FILE, "a", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            path.name,
            round(image_size_kb, 2),
            round(ascon_time, 6),
            round(rsa_time, 6),
            round(total_encryption_time, 6),
            round(transmission_time, 6),
            round(overall_delay, 6),
            round(throughput, 2)
        ])


# ----------------------------
# FILE EVENT HANDLER
# ----------------------------
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
            print(f"Skipping root file : {path}")
            return

        print(f"New image detected : {path}")

        if not wait_until_file_ready(path):
            print(f"File not ready : {path}")
            return

        try:
            send_image(path)

            sent_files.add(path)

            print(f"Sent successfully : {path.name}")

        except Exception as e:
            print(f"Send failed for {path}")
            print(f"Error : {e}")

    def on_created(self, event):

        if event.is_directory:
            return

        self.process_image(
            Path(event.src_path)
        )

    def on_moved(self, event):

        if event.is_directory:
            return

        self.process_image(
            Path(event.dest_path)
        )


# ----------------------------
# SCAN EXISTING FILES
# ----------------------------
def scan_existing_files():

    for path in WATCH_FOLDER.rglob("*"):

        if (
            path.is_file()
            and path.suffix.lower()
            in VALID_EXTENSIONS
        ):

            if (
                path.parent != WATCH_FOLDER
                and path not in sent_files
            ):

                try:
                    if wait_until_file_ready(
                        path,
                        timeout=3
                    ):

                        send_image(path)

                        sent_files.add(path)

                        print(f"Startup sent : {path}")

                except Exception as e:
                    print(
                        f"Startup send failed for {path}"
                    )

                    print(f"Error : {e}")


# ----------------------------
# MAIN
# ----------------------------
def main():

    WATCH_FOLDER.mkdir(
        parents=True,
        exist_ok=True
    )

    print("\n========================================")
    print(f"Watching Folder : {WATCH_FOLDER}")
    print(f"Receiver         : {HOST}:{PORT}")
    print(f"Public Key       : {PUBLIC_KEY_PATH}")
    print("========================================\n")

    scan_existing_files()

    observer = Observer()

    observer.schedule(
        Handler(),
        str(WATCH_FOLDER),
        recursive=True
    )

    observer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()


# ----------------------------
# START PROGRAM
# ----------------------------
if __name__ == "__main__":
    main() ithile encryption edukkne time add cheyrthne codile
