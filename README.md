# Secure File Encryption Utility
## Overview
This project is a secure file encryption utility that allows users to encrypt and decrypt files using AES-256 in CBC mode. It features password-based key derivation (PBKDF2), file integrity verification (SHA-256 checksums), and both CLI and GUI interfaces. The tool is designed to demonstrate skills in cryptography, secure coding, file handling, and user interface design, making it ideal for showcasing in a software engineering portfolio, especially for roles requiring data security.
## Features

- Encryption/Decryption: Securely encrypt and decrypt files of any type using AES-256-CBC.
- Key Derivation: Derive encryption keys from passwords using PBKDF2 with a random salt and 100,000 iterations.
- Integrity Verification: Verify file integrity using SHA-256 checksums to detect tampering or corruption.
- Interfaces:
- - Command-line interface (CLI) for advanced users.
- - Graphical user interface (GUI) using Tkinter for accessibility.
- Error Handling: Robust validation for file paths, password length, and decryption failures.
- Security: Random IV per encryption, secure key derivation, and padding for AES compliance.


## Prerequisites

- Python 3.8 or higher
- Required library: cryptographypip install cryptography


## Setup

1. Clone the repository:
````
git clone <repository-url>
cd secure-file-encryption
````

2. Install dependencies:
````
pip install cryptography
````

## Usage
**Command-Line Interface (CLI)**
Run encryptor.py to encrypt or decrypt files.

- Encrypt a file:
````
python encryptor.py encrypt sample.txt mypassword123
````

- - Output: sample.txt.enc (encrypted file containing salt, IV, ciphertext, and checksum).
- - Password must be at least 8 characters.


- Decrypt a file:
````
python encryptor.py decrypt sample.txt.enc mypassword123
````

- - Output: sample.txt.dec (decrypted file).
- - Fails if password is incorrect or file is corrupted (verified via checksum).




#
