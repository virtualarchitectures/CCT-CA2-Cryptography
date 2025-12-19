# CCT CA2 - Cryptography

A project demonstrating practical AES encryption and SHA hashing in Python.

## Overview

This project contains two applications demonstrating cryptographic concepts:

1. **AES-GCM Encryption** (`aes_gcm.py`) - Demonstrates symmetric encryption using AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
2. **SHA Hashing** (`sha_hashing.py`) - Demonstrates cryptographic hashing using SHA-1, SHA-256, and SHA3-256 algorithms

## Prerequisites

- Python 3.14 or higher
- `uv` package manager (recommended) or `pip`

## Installation

### Using uv (recommended)

```bash
uv sync
```

### Using pip

```bash
pip install cryptography>=46.0.3
```

## Running the Applications

### 1. AES-GCM Encryption Demo

**Run the application:**

```bash
python src/aes_gcm.py
```

This application demonstrates secure encryption and decryption of sensitive data (simulating a customer ID number). The output includes:

1. **Key Generation**: A 256-bit encryption key is generated
2. **Encryption**: The plaintext "123-456-789" is encrypted, producing:
   - A unique nonce (number used once)
   - Encrypted ciphertext
3. **Database Simulation**: Shows how encrypted data would be stored in a database
4. **Decryption**: Retrieves and decrypts the data back to the original plaintext
5. **Integrity Verification**: Confirms the decrypted data matches the original
6. **Tamper Detection**: Demonstrates how AES-GCM detects tampering by modifying the ciphertext and attempting to decrypt it (this will fail with an authentication error)

**Summary:**

- AES-GCM provides both encryption and authentication
- Each encryption uses a unique nonce
- Any tampering with the ciphertext is automatically detected during decryption
- The authentication tag prevents unauthorized modifications

### 2. SHA Hashing Demo

**Run the application:**

```bash
python src/sha_hashing.py
```

This application demonstrates cryptographic hashing for file integrity verification. The output includes:

1. **File Upload Simulation**: Simulates uploading a product image file
2. **SHA-1 Hash**: Computes SHA-1 hash (with warning that it's deprecated)
3. **SHA-256 Hash**: Computes the secure SHA-256 hash
4. **SHA3-256 Hash**: Computes the modern SHA3-256 hash
5. **Database Storage**: Shows how file metadata and hashes are stored
6. **Integrity Verification**: Verifies the file hasn't been tampered with by comparing hashes
7. **Tamper Detection**: Demonstrates hash mismatch when file content is modified
8. **Hash Comparison**: Shows the output lengths of different hash algorithms (160, 256, and 256 bits)
9. **Deterministic Property**: Proves that hashing the same data always produces the same hash
10. **Performance Comparison**: Benchmarks SHA-256 vs SHA3-256 performance on a 1 MB file

**Summary:**

- Hash functions are one-way (cannot reverse to get original data)
- Even a single byte change produces a completely different hash
- Hashes are deterministic (same input = same output)
- SHA-1 is deprecated and should not be used in production
- SHA-256 is currently the industry standard
- SHA3-256 is more secure but slightly slower than SHA-256

## Security Notes

- In production, encryption keys must be stored securely (e.g., using a Key Management Service)
- Never hardcode encryption keys in your source code
- SHA-1 is cryptographically broken and should not be used for security purposes
- Always use the latest recommended algorithms (currently SHA-256 or SHA3-256 for hashing)

## Disclaimer

This project is for educational purposes as part of CCT CA2 coursework. These code examples should not be used in production environments.
