import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt: bytes = None) -> tuple:
    """Derive a 256-bit key from password using PBKDF2"""
    if not salt:
        salt = os.urandom(16) #generate random salt for encryption
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_file(input_file: str, password: str) -> None:
    """Encrypt a file using AES (CBC mode with PKCS7 padding)."""
    if len(password) < 8:
        raise ValueError("Password must be at leaast 8 characters long.")

    #read input file
    with open(input_file, 'rb') as f:
        data = f.read()

    #derive key and salt from password
    key, salt = derive_key(password)
    iv = os.urandom(16) # random IV for CBC mode

    #encrypt data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16-len(data) % 16) #pad to AES block size
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    #compute checksum of original file
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    checksum = digest.finalize()

    #write encrypted file (sale + iv + cyphertext + checksum)
    output_file = input_file + '.enc'
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext + checksum)
    print(f"Encrypted file saved as {output_file}")

def decrypt_file(input_file: str, password: str) -> None:
    """Decrypt a file and verify integrity"""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    
    #read encrypted file
    with open(input_file, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read(-32)
        stored_checksum = f.read(32)

    #derive key
    key, _ = derive_key(password, salt)

    #decrypt data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted_data = decrypted_padded.rstrip(b'\0') #remove padding

    #verify checksum
    digest = hashes.Hash(hashes.SHA256())
    digest.update(decrypted_data)
    computed_checksum = digest.finalize()
    if computed_checksum != stored_checksum:
        raise ValueError("Integrity check failed: File may be corrupted or password incorrect")
    
    #write decrypted file
    output_file = input_file.replace('.enc', '.dec')
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted file saved as {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Secure File Encryption Utility")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("file", help="Input file path")
    parser.add_argument("password", help="Password for encryption/decryption")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("Error: File does not exist")
        return

    try:
        if args.mode == "encrypt":
            encrypt_file(args.file, args.password)
        elif args.mode == "decrypt":
            decrypt_file(args.file, args.password)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
