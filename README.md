# Medical Image Receiver System

## Project Overview

The **Medical Image Receiver System** is a secure platform for transferring medical images from a Raspberry Pi (sender) to a laptop/computer (receiver) on a local network. Built with hybrid encryption combining ASCON (symmetric) and RSA (asymmetric) cryptography, it ensures confidential, authenticated transfer of patient data.

### Core Goals
- **Confidential transfer** of patient images between devices on a trusted network
- **Simple, patient-wise organization** of received images on the receiver machine
- **Minimal setup** to run on low-power hardware (Raspberry Pi)
- **Hybrid encryption** for strong security with efficient performance

---

## Key Features

✅ **Automatic Detection** — Watches a configured directory for new images organized by patient name  
✅ **Hybrid Encryption** — ASCON (symmetric) + RSA (asymmetric) for optimal security and performance  
✅ **Metadata Packaging** — Combines patient metadata and image bytes into a single encrypted packet  
✅ **One-Time Session Keys** — Generates fresh ASCON keys per transmission  
✅ **Secure TCP Transfer** — Encrypted packet delivery over socket connection  
✅ **Organized Storage** — Receiver automatically creates patient-specific folders with timestamped filenames  
✅ **Integrity Verification** — AEAD semantics provided by ASCON  

---

## System Architecture

### How It Works (High Level)

#### 1️⃣ Patient Image Storage on Raspberry Pi

Images should be organized by patient name in the sender directory:

```
/home/pi/sender/img/
├── Rahul/
│   ├── image1.jpg
│   └── image2.png
├── Anjali/
│   └── scan1.jpg
```

**Directory Layout:** `/home/pi/sender/img/<PatientName>/<image-files>`

#### 2️⃣ Image Detection & Encryption

- File-watcher (inotify or polling) detects newly added image files
- Sender builds encrypted packet containing:
  - Patient name (from folder name)
  - Filename and timestamp
  - MIME type and optional metadata
  - Raw image bytes (or compressed representation)
- ASCON encryption with randomly generated session key
- Session key encrypted with receiver's RSA public key (hybrid encryption)

**See:** [Sender-side implementation](screenshots/3.jpeg)

#### 3️⃣ Secure Transfer to Receiver

- Sender connects to receiver's configured host and TCP port
- Encrypted packet transmitted over socket
- Receiver listens for incoming connections, validates packets, and acknowledges receipt
- Optional: TLS for socket transport or application-level integrity checks

#### 4️⃣ Saving and Organizing Images on Receiver

- Receiver uses RSA private key to decrypt ASCON session key
- Session key used to decrypt payload and extract patient name and image bytes
- Patient directory created automatically (e.g., `./images/<PatientName>/`)
- Image saved with timestamped filename to prevent overwrites

**See:** [Receiver-side implementation](screenshots/2.jpeg)

---

## Performance Metrics

The implementation has been benchmarked for efficiency:

| Metric | Details |
|--------|---------|
| **Encryption Time** | Sub-millisecond for typical medical images |
| **Decryption Time** | Optimized hybrid decryption process |
| **Transmission Time** | Low-latency TCP transfer |
| **Throughput** | High-speed image transmission capability |
| **End-to-End Delay** | Minimal latency from detection to storage |

**View Full Analysis:** [Performance Metrics](screenshots/1.jpeg)

---

## Requirements

- **Sender:** Raspberry Pi or Linux machine (Python 3.8+)
- **Receiver:** Linux/macOS/Windows with Python 3.8+
- **Python Dependencies:**
  - ASCON implementation
  - `pycryptodome` or `cryptography` (RSA operations)
  - `watchdog` (file monitoring)
  - Standard socket/networking libraries

- **Cryptographic Assets:**
  - RSA keypair (2048 bits or higher recommended)
  - Public key accessible by sender
  - Private key secured on receiver

---

## Setup Instructions

### 1. Generate RSA Keypair (on Receiver)

```bash
# Generate 2048-bit RSA keypair
openssl genrsa -out receiver_private.pem 2048
openssl rsa -in receiver_private.pem -pubout -out receiver_public.pem
```

Copy `receiver_public.pem` to the sender machine.

### 2. Configure Sender Settings

Create or update sender configuration with:
- Receiver host and port
- Path to `receiver_public.pem`
- Image directory path (`/home/pi/sender/img/`)

### 3. Configure Receiver Settings

Create or update receiver configuration with:
- Listening port
- Path to `receiver_private.pem`
- Storage directory for received images

---

## Running the System

### Start Receiver First

```bash
python receiver.py
```

Receiver listens for incoming connections and waits for encrypted packets.

### Start Sender on Raspberry Pi

```bash
python sender.py
```

When a new image is placed in `/home/pi/sender/img/<PatientName>/`, the sender:
1. Detects the new file
2. Packages and encrypts the data
3. Transmits to receiver
4. Receiver decrypts and stores in organized patient folder

---

## Security Best Practices

🔒 **Private Key Protection** — Keep receiver private key secret with restricted file permissions  
🔒 **Strong RSA Keys** — Use 2048 bits or higher; rotate keys periodically  
🔒 **Network Security** — Consider TLS or VPN if network-level security is required  
🔒 **Input Validation** — Sanitize patient names to prevent path traversal or filesystem injection  
🔒 **File Type Restrictions** — Limit accepted image formats; scan for malware in untrusted environments  
🔒 **Access Control** — Restrict receiver listening port to trusted networks only  

---

## Project Structure

```
secure_image_transmission_using_hybrid_encryption/
├── sender.py              # Sender-side implementation
├── receiver.py            # Receiver-side implementation
├── screenshots/           # Implementation and performance screenshots
│   ├── 1.jpeg            # Performance analysis
│   ├── 2.jpeg            # Receiver implementation
│   └── 3.jpeg            # Sender implementation
└── README.md             # This file
```

---

## Implementation Screenshots

- **[1.jpeg](screenshots/1.jpeg)** — Performance analysis showing encryption/decryption time, throughput, and end-to-end delay
- **[2.jpeg](screenshots/2.jpeg)** — Receiver-side implementation details
- **[3.jpeg](screenshots/3.jpeg)** — Sender-side implementation details

---

## License

This project is provided as-is for educational and medical application purposes.

---

## Support & Contributions

For issues, feature requests, or contributions, please open an issue or pull request on GitHub.
