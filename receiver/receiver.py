        import os
import time
import socket
import csv
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

SAVE_DIR = Path(
    r"C:\Users\abhijith\secure_image_transmission_using_hybrid_encryption\receiver\static\images"
)

SAVE_DIR.mkdir(
    parents=True,
    exist_ok=True
)

CSV_FILE = "receiver_performance_log.csv"


# ----------------------------
# CREATE CSV HEADER
# ----------------------------
if not os.path.exists(CSV_FILE):

    with open(CSV_FILE, "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "Filename",
            "ImageSizeKB",
            "RSA_Decryption_Time",
            "ASCON_Decryption_Time",
            "Payload_Parsing_Time",
            "File_Save_Time",
            "Total_Receiver_Time"
        ])


# ----------------------------
# SANITIZE NAME
# ----------------------------
def sanitize_name(name: str) -> str:

    allowed = []

    for ch in name.strip():

        if ch.isalnum() or ch in (" ", "_", "-"):
            allowed.append(ch)

    cleaned = "".join(allowed).strip()

    return cleaned if cleaned else "unknown_patient"


# ----------------------------
# RECEIVE EXACT DATA
# ----------------------------
def recv_exact(conn, n: int) -> bytes:

    data = b""

    while len(data) < n:

        chunk = conn.recv(n - len(data))

        print(f"Received chunk: {len(chunk)} bytes")

        if not chunk:
            raise ConnectionError(
                "Connection closed early"
            )

        data += chunk

    return data


# ----------------------------
# PARSE SECURE PAYLOAD
# ----------------------------
def parse_secure_payload(payload: bytes):

    """
    Payload format:
    [2 bytes patient_name_len]
    [patient_name bytes]
    [2 bytes filename_len]
    [filename bytes]
    [image bytes]
    """

    print(
        f"Parsing secure payload size: "
        f"{len(payload)} bytes"
    )

    offset = 0

    if len(payload) < 2:
        raise ValueError("Payload too short")

    patient_len = int.from_bytes(
        payload[offset:offset + 2],
        "big"
    )

    offset += 2

    if len(payload) < offset + patient_len + 2:
        raise ValueError(
            "Invalid patient field"
        )

    patient_name = payload[
        offset:offset + patient_len
    ].decode(
        "utf-8",
        errors="replace"
    )

    offset += patient_len

    filename_len = int.from_bytes(
        payload[offset:offset + 2],
        "big"
    )

    offset += 2

    if len(payload) < offset + filename_len:
        raise ValueError(
            "Invalid filename field"
        )

    filename = payload[
        offset:offset + filename_len
    ].decode(
        "utf-8",
        errors="replace"
    )

    offset += filename_len

    image_bytes = payload[offset:]

    if not image_bytes:
        raise ValueError(
            "No image bytes found"
        )

    return (
        patient_name,
        filename,
        image_bytes
    )


# ----------------------------
# LOAD PRIVATE KEY
# ----------------------------
with open(PRIVATE_KEY_PATH, "rb") as f:

    private_key = (
        serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    )


# ----------------------------
# START SERVER
# ----------------------------
server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind((HOST, PORT))

server.listen(5)

print("\n========================================")
print(f"Receiver listening : {HOST}:{PORT}")
print(f"Save Directory      : {SAVE_DIR}")
print("========================================\n")


# ----------------------------
# RECEIVE LOOP
# ----------------------------
while True:

    conn, addr = server.accept()

    print(f"\nConnected from: {addr}")

    try:

        # --------------------------------
        # TOTAL RECEIVER START
        # --------------------------------
        total_start = time.perf_counter()

        # --------------------------------
        # RECEIVE PACKET
        # --------------------------------
        total_size = int.from_bytes(
            recv_exact(conn, 8),
            "big"
        )

        packet = recv_exact(
            conn,
            total_size
        )

        # --------------------------------
        # EXTRACT FIELDS
        # --------------------------------
        rsa_len = int.from_bytes(
            packet[:2],
            "big"
        )

        offset = 2

        rsa_ct = packet[
            offset:offset + rsa_len
        ]

        offset += rsa_len

        nonce = packet[
            offset:offset + 16
        ]

        offset += 16

        ciphertext = packet[offset:]

        if len(nonce) != 16:
            raise ValueError(
                "Invalid nonce length"
            )

        # --------------------------------
        # RSA DECRYPTION
        # --------------------------------
        rsa_start = time.perf_counter()

        session_key = private_key.decrypt(
            rsa_ct,

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

        print(
            f"Session key decrypted"
        )

        # --------------------------------
        # ASCON DECRYPTION
        # --------------------------------
        ascon_start = time.perf_counter()

        plaintext = decrypt(
            session_key,
            nonce,
            AAD,
            ciphertext
        )

        ascon_end = time.perf_counter()

        ascon_time = (
            ascon_end - ascon_start
        )

        if plaintext is None:

            print(
                "Authentication failed"
            )

            continue

        # --------------------------------
        # PAYLOAD PARSING
        # --------------------------------
        parsing_start = (
            time.perf_counter()
        )

        (
            patient_name,
            original_filename,
            image_bytes
        ) = parse_secure_payload(
            plaintext
        )

        parsing_end = (
            time.perf_counter()
        )

        parsing_time = (
            parsing_end - parsing_start
        )

        patient_name = sanitize_name(
            patient_name
        )

        # --------------------------------
        # CREATE PATIENT FOLDER
        # --------------------------------
        patient_folder = (
            SAVE_DIR / patient_name
        )

        patient_folder.mkdir(
            parents=True,
            exist_ok=True
        )

        # --------------------------------
        # FILE EXTENSION
        # --------------------------------
        ext = Path(
            original_filename
        ).suffix.lower()

        if ext not in [
            ".jpg",
            ".jpeg",
            ".png"
        ]:
            ext = ".jpg"

        save_name = (
            f"{int(time.time())}_"
            f"{Path(original_filename).stem}"
            f"{ext}"
        )

        save_path = (
            patient_folder / save_name
        )

        # --------------------------------
        # SAVE IMAGE
        # --------------------------------
        save_start = (
            time.perf_counter()
        )

        with open(save_path, "wb") as f:
            f.write(image_bytes)

        save_end = (
            time.perf_counter()
        )

        save_time = (
            save_end - save_start
        )

        # --------------------------------
        # TOTAL RECEIVER TIME
        # --------------------------------
        total_end = (
            time.perf_counter()
        )

        total_receiver_time = (
            total_end - total_start
        )

        # --------------------------------
        # IMAGE SIZE
        # --------------------------------
        image_size_kb = (
            len(image_bytes) / 1024
        )

        # --------------------------------
        # PRINT PERFORMANCE
        # --------------------------------
        print("\n========== RECEIVER PERFORMANCE ==========")

        print(
            f"Image Size              : "
            f"{image_size_kb:.2f} KB"
        )

        print(
            f"RSA Decryption Time     : "
            f"{rsa_time:.6f} sec"
        )

        print(
            f"ASCON Decryption Time   : "
            f"{ascon_time:.6f} sec"
        )

        print(
            f"Payload Parsing Time    : "
            f"{parsing_time:.6f} sec"
        )

        print(
            f"File Save Time          : "
            f"{save_time:.6f} sec"
        )

        print(
            f"Total Receiver Time     : "
            f"{total_receiver_time:.6f} sec"
        )

        print("==========================================\n")

        print(f"Saved : {save_path}")

        # --------------------------------
        # SAVE PERFORMANCE TO CSV
        # --------------------------------
        with open(
            CSV_FILE,
            "a",
            newline=""
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                original_filename,
                round(image_size_kb, 2),
                round(rsa_time, 6),
                round(ascon_time, 6),
                round(parsing_time, 6),
                round(save_time, 6),
                round(total_receiver_time, 6)
            ])

    except Exception as e:

        print(f"Error : {e}")

    finally:

        conn.close()ithilum decryption timun size dd cheytine
