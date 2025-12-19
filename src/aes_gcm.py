import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_data(key: bytes, plaintext: str) -> dict:
    # Create AES-GCM cipher instance
    aesgcm = AESGCM(key)

    # Generate a unique 12-byte nonce (must be unique for each encryption)
    nonce = os.urandom(12)

    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode("utf-8")

    # Encrypt the data
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Return base64-encoded values for storage
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_data(key: bytes, encrypted_data: dict) -> str:
    # Create AES-GCM cipher instance
    aesgcm = AESGCM(key)

    # Decode the base64-encoded values
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])

    # Decrypt and verify authentication tag
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    # Convert bytes back to string
    return plaintext_bytes.decode("utf-8")


def main():
    # Step 1: Generate a secure 256-bit encryption key
    # In production the key would be stored in a secure key management system
    key = AESGCM.generate_key(bit_length=256)
    print("1. Generated 256-bit key")
    print(f"Key (base64): {base64.b64encode(key).decode('utf-8')[:40]}...")

    # Step 2: Encrypt sensitive customer data
    sensitive_data = "123-456-789"
    print("2. Encrypting sensitive data")
    print(f"Plaintext: {sensitive_data}")

    encrypted = encrypt_data(key, sensitive_data)
    print(f"Nonce: {encrypted['nonce']}")
    print(f"Ciphertext: {encrypted['ciphertext']}")

    # Step 3: Store encrypted data in database
    # In production you would store both the nonce and ciphertext
    print("3. Storing in database...")
    database_record = {
        # Example database record
        "customer_id": "CUSTOMER_001",
        "name": "John Doe",
        "encrypted_data_nonce": encrypted["nonce"],
        "encrypted_data_data": encrypted["ciphertext"],
    }
    print(f"Record stored for customer: {database_record['name']}")

    # Step 4: Retrieve and decrypt data
    print("4. Retrieving and decrypting data...")
    encrypted_from_db = {
        "nonce": database_record["encrypted_data_nonce"],
        "ciphertext": database_record["encrypted_data_data"],
    }

    decrypted_data = decrypt_data(key, encrypted_from_db)
    print(f"Decrypted data: {decrypted_data}")

    # Step 5: Verify integrity
    if decrypted_data == sensitive_data:
        print("5. Verification: SUCCESS")
        print("Data integrity confirmed - no tampering detected")
    else:
        print("5. Verification: FAILED")

    # Demonstrate tamper detection
    print("6. Demonstrating tamper detection...")
    try:
        # Modify the ciphertext to simulate tampering
        tampered = encrypted.copy()

        # Convert base64 to raw bytes for manipulation
        tampered_bytes = base64.b64decode(tampered["ciphertext"])

        # Replace the first byte with X
        tampered_bytes = b"X" + tampered_bytes[1:]

        # Encode back to base64
        tampered["ciphertext"] = base64.b64encode(tampered_bytes).decode("utf-8")

        # Attempt to decrypt tampered data
        decrypt_data(key, tampered)
        print("ERROR: Tampering not detected!")
    except Exception as e:
        print(f"Tampering detected: {type(e).__name__}")
        print("AES-GCM successfully prevented unauthorised modification")


if __name__ == "__main__":
    main()
