# Medical Image Receiver System

## Project Overview

The Medical Image Receiver System is a secure image transfer and viewing platform designed for medical data. It uses a Raspberry Pi as the sender and a laptop or computer as the receiver. Medical images are transferred over a local network in encrypted form, decrypted only at the receiver side, and then displayed in a web dashboard organized by patient name.

The main purpose of the project is to ensure that patient images are transferred securely and stored in a structured way for easy viewing.

---

## How the Project Works

The project works in four main stages:

### 1. Patient Image Storage on Raspberry Pi
On the Raspberry Pi, images are stored inside folders named after patients.

Example:

```text
/home/pi/sender/img/
├── Rahul Kumar/
│   ├── image1.jpg
│   └── image2.png
├── Anjali/
│   └── scan1.jpg
```

## 2. Image Detection and Encryption
The Raspberry Pi continuously watches the main image directory for new image files. Each image is stored inside a folder named after the patient, so the folder name itself is used as the patient name. When a new image is detected, the sender program reads the patient name from the folder, reads the image file, and prepares a data packet containing the patient name, the image filename, and the image content.

To secure the transfer, the project uses hybrid encryption. First, the complete data packet is encrypted using ASCON, which protects the patient details and the image data. Then, the temporary ASCON key used for that encryption is itself encrypted using RSA. This method ensures that the image data remains confidential and that only the receiver can unlock the session key needed for decryption.

## 3. Secure Transfer to Receiver
Once the data has been encrypted, the Raspberry Pi sends it to the receiver machine through socket communication over Wi-Fi or a local network. The receiver system remains active and listens on a specific port for incoming connections from the sender.

When the encrypted packet arrives, the receiver accepts the connection and reads the packet safely. It first uses its RSA private key to recover the temporary ASCON session key. After obtaining that session key, it uses ASCON decryption to recover the original payload. From this decrypted payload, the receiver obtains the patient name, the image filename, and the image data.

## 4. Saving and Organizing Images
After successful decryption, the receiver stores the image in a structured way. It checks whether a folder already exists for the patient name extracted from the packet. If the folder does not exist, the receiver creates it automatically.

The decrypted image is then saved inside that patient’s folder, usually with a timestamp added to the filename so that files do not overwrite one another. This creates a patient-wise storage system where each patient’s images are grouped together in a separate folder. As a result, the received medical data remains organized and easy to access later through the web dashboard.## 2. Image Detection and Encryption
The Raspberry Pi continuously watches the main image directory for new image files. Each image is stored inside a folder named after the patient, so the folder name itself is used as the patient name. When a new image is detected, the sender program reads the patient name from the folder, reads the image file, and prepares a data packet containing the patient name, the image filename, and the image content.

To secure the transfer, the project uses hybrid encryption. First, the complete data packet is encrypted using ASCON, which protects the patient details and the image data. Then, the temporary ASCON key used for that encryption is itself encrypted using RSA. This method ensures that the image data remains confidential and that only the receiver can unlock the session key needed for decryption.

