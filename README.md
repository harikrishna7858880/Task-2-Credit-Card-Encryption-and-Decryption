# Task-2-Credit-Card-Encryption-and-Decryption
Task 2 Credit Card Encryption and Decryption Description:This is one such project which helps you combine your cloud computing skills also in your cyber security journey. Access control management and cryptography are the key skills for this project.



To work on a project involving credit card encryption and decryption, you need to understand and implement cryptographic techniques. This project involves securely storing and retrieving credit card information using encryption.

Key Steps in the Project:
Understanding Encryption and Decryption:

Encryption is the process of converting plaintext into ciphertext using a cryptographic algorithm and a key.
Decryption is the process of converting ciphertext back into plaintext using the same algorithm and key.
Choosing a Cryptographic Algorithm:

For strong security, use well-known and tested algorithms such as AES (Advanced Encryption Standard).
Implementing Encryption and Decryption:

You will need a library that supports cryptographic functions. In Python, the cryptography library is commonly used.
Example Implementation in Python:
Install the cryptography library:

pip install cryptography
Encryption and Decryption Code:

Python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to generate a key from a password
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data
def encrypt_data(data: str, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

# Example usage
password = "securepassword"
salt = os.urandom(16)
key = generate_key(password, salt)

credit_card_info = "1234-5678-9876-5432"
encrypted_credit_card_info = encrypt_data(credit_card_info, key)
print(f"Encrypted: {encrypted_credit_card_info}")

decrypted_credit_card_info = decrypt_data(encrypted_credit_card_info, key)
print(f"Decrypted: {decrypted_credit_card_info}")
Explanation:
Key Generation:

A key is derived from a password using PBKDF2 with HMAC-SHA256, salt, and multiple iterations to make brute-force attacks more difficult.
Encryption:

Data is padded to be compatible with the block size of the AES algorithm.
A random initialization vector (IV) is generated for each encryption to ensure the same plaintext results in different ciphertexts.
The AES algorithm in CBC mode is used for encryption.
Decryption:

The IV is extracted from the encrypted data.
The AES algorithm in CBC mode is used for decryption.
Padding is removed to retrieve the original plaintext.
Security Considerations:
Do not hard-code passwords or keys in your code. Store them securely, possibly in environment variables or a secrets management service.
Use a unique salt for each key derivation to ensure the same password does not generate the same key.
This project combines cloud computing and cybersecurity by securely managing credit card information using encryption, which is a critical skill in protecting sensitive data.
