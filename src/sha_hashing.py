import hashlib
import os
import time


def compute_sha1_hash(data: bytes) -> str:
    # Compute SHA-1 hash of data.
    # WARNING! SHA-1 is deprecated and should NOT be used in production.
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.hexdigest()


def compute_sha256_hash(data: bytes) -> str:
    # Compute SHA-256 hash of data.
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def compute_sha3_256_hash(data: bytes) -> str:
    # Compute SHA3-256 hash of data
    sha3_256 = hashlib.sha3_256()
    sha3_256.update(data)
    return sha3_256.hexdigest()


def verify_file_integrity(
    data: bytes, stored_hash: str, algorithm: str = "sha256"
) -> bool:
    if algorithm == "sha1":
        computed_hash = compute_sha1_hash(data)
    elif algorithm == "sha256":
        computed_hash = compute_sha256_hash(data)
    elif algorithm == "sha3_256":
        computed_hash = compute_sha3_256_hash(data)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    return computed_hash == stored_hash


def main():
    # Step 1: Simulate a customer file upload
    print("1. Simulating customer file upload...")
    customer_file = "product_image_12345.jpg"
    # Simulate file content (in production this would be actual file bytes)
    file_content = b"This is the content of the uploaded product image file."
    print(f"File: {customer_file}")
    print(f"Size: {len(file_content)} bytes")

    # Step 2: Demonstrate SHA-1
    print("2. Computing SHA-1 hash...")
    sha1_hash = compute_sha1_hash(file_content)
    print(f"SHA-1:   {sha1_hash}")

    # Step 3: Compute SHA-256 hash
    print("3. Computing SHA-256 hash...")
    sha256_hash = compute_sha256_hash(file_content)
    print(f"SHA-256: {sha256_hash}")

    # Step 4: Compute SHA3-256 hash
    print("4. Computing SHA3-256 hash...")
    sha3_256_hash = compute_sha3_256_hash(file_content)
    print(f"SHA3-256: {sha3_256_hash}")

    # Step 5: Simulate storing file metadata in database
    print("5. Simulate storing file metadata in database...")
    database_record = {
        "file_id": "FILE_001",
        "customer_id": "CUSTOMER_001",
        "filename": customer_file,
        "upload_timestamp": "2025-12-15T10:30:00Z",
        "sha256_hash": sha256_hash,
        "sha3_256_hash": sha3_256_hash,
        "file_size": len(file_content),
    }
    # Display file and customer details for validation
    print(f"Record stored for file: {database_record['filename']}")
    print(f"Customer: {database_record['customer_id']}")
    # Display the first 32 characters of each hash
    print(f"SHA-256:  {database_record['sha256_hash'][:32]}...")
    print(f"SHA3-256: {database_record['sha3_256_hash'][:32]}...")

    # Step 6: Verify file integrity
    print("6. Verifying file integrity...")
    is_valid = verify_file_integrity(file_content, sha256_hash, "sha256")
    if is_valid:
        print("Verification: SUCCESS")
        print("File integrity confirmed - no tampering detected")
    else:
        print("Verification: FAILED")
        print("File may have been corrupted or tampered with")

    # Step 7: Demonstrate tamper detection
    print("7. Demonstrating tamper detection...")
    print("Simulating file corruption (changing one byte)...")
    # Change first byte
    tampered_content = b"X" + file_content[1:]
    print(f"Original first byte: {file_content[0]:02x}")
    print(f"Tampered first byte: {tampered_content[0]:02x}")

    is_tampered_valid = verify_file_integrity(tampered_content, sha256_hash, "sha256")
    print("Verifying tampered file against stored hash...")
    if is_tampered_valid:
        print("ERROR: Tampering not detected!")
    else:
        print("Tampering detected: Hash mismatch")
        print("Original hash:  " + sha256_hash)
        print("Computed hash:  " + compute_sha256_hash(tampered_content))
        print("SHA successfully prevented acceptance of corrupted file")

    # Step 8: Compare hash outputs for different algorithms
    print("8. Comparing hash properties...")
    print(
        f"SHA-1 output length:    {len(sha1_hash) * 4} bits ({len(sha1_hash)} hex chars)"
    )
    print(
        f"SHA-256 output length:  {len(sha256_hash) * 4} bits ({len(sha256_hash)} hex chars)"
    )
    print(
        f"SHA3-256 output length: {len(sha3_256_hash) * 4} bits ({len(sha3_256_hash)} hex chars)"
    )

    # Step 9: Demonstrate deterministic property
    print("9. Demonstrating deterministic property...")
    print("Computing hash of same data multiple times...")
    hash1 = compute_sha256_hash(file_content)
    hash2 = compute_sha256_hash(file_content)
    hash3 = compute_sha256_hash(file_content)
    print(f"Hash 1: {hash1[:32]}...")
    print(f"Hash 2: {hash2[:32]}...")
    print(f"Hash 3: {hash3[:32]}...")
    if hash1 == hash2 == hash3:
        print("All hashes identical - deterministic property confirmed")

    # Step 10: Performance comparison
    print("10. Simulating high-throughput scenario...")
    # Generate 1 MB random data for demonstration
    large_file = os.urandom(1024 * 1024)
    print(f"Processing {len(large_file):,} bytes...")

    # SHA-256 timing
    start = time.perf_counter()
    for _ in range(10):
        compute_sha256_hash(large_file)
    sha256_time = time.perf_counter() - start

    # SHA3-256 timing
    start = time.perf_counter()
    for _ in range(10):
        compute_sha3_256_hash(large_file)
    sha3_time = time.perf_counter() - start

    print(f"SHA-256 (10 iterations):  {sha256_time:.4f} seconds")
    print(f"SHA3-256 (10 iterations): {sha3_time:.4f} seconds")
    print(
        f"Performance ratio: SHA3-256 is {sha3_time / sha256_time:.2f}x slower than SHA-256"
    )


if __name__ == "__main__":
    main()
