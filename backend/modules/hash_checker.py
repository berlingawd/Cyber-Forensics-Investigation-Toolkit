"""
Evidence Integrity Verification Module
======================================
Calculates cryptographic hashes (MD5, SHA1, SHA256) to preserve evidence integrity.
Used by DFIR teams to verify that evidence has not been altered after collection.
"""

import hashlib
from datetime import datetime
from pathlib import Path


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate cryptographic hash of a file.

    Args:
        file_path: Path to the file
        algorithm: One of 'md5', 'sha1', or 'sha256'

    Returns:
        Hex string of the hash value
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
    }
    if algorithm.lower() not in hash_funcs:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use md5, sha1, or sha256")

    hasher = hash_funcs[algorithm.lower()]()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)

    return hasher.hexdigest()


def verify_evidence_integrity(file_path: str) -> dict:
    """
    Calculate all three hashes for an evidence file.

    Returns:
        Dictionary with file name, hashes, timestamp, and status
    """
    path = Path(file_path)
    if not path.exists():
        return {
            "file_name": path.name,
            "md5": None,
            "sha1": None,
            "sha256": None,
            "timestamp_collected": datetime.now().isoformat(),
            "evidence_status": "ERROR - File not found",
        }

    try:
        md5_hash = calculate_file_hash(file_path, "md5")
        sha1_hash = calculate_file_hash(file_path, "sha1")
        sha256_hash = calculate_file_hash(file_path, "sha256")

        return {
            "file_name": path.name,
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "timestamp_collected": datetime.now().isoformat(),
            "evidence_status": "VERIFIED - Integrity preserved",
        }
    except Exception as e:
        return {
            "file_name": path.name,
            "md5": None,
            "sha1": None,
            "sha256": None,
            "timestamp_collected": datetime.now().isoformat(),
            "evidence_status": f"ERROR - {str(e)}",
        }
