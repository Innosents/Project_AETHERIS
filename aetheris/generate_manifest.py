"""
Project AETHERIS - Generate Manifest
Executes recursive SHA-256 cryptographic hashing across all Python source modules within the designated project namespace. Serializes an ISO 8601-anchored deployment manifest to guarantee codebase integrity and enforce immutable post-audit constitutional states.
"""

import os
import hashlib
import json
import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AETHERIS_LOCKDOWN] - %(message)s')

def hash_file(filepath: str) -> str:
    """Calculates the SHA-256 checksum of a target file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_deployment_manifest(target_dir: str, output_file: str):
    """Recursively hashes the AETHERIS namespace and outputs a cryptographic manifest."""
    manifest = {
        "deployment_status": "LOCKED",
        "protocol": "Project AETHERIS Constitution (v2.4)",
        "iso_8601_anchor": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "execution_matrices": {}
    }

    logging.info(f"Initiating recursive SHA-256 sweep of {target_dir}...")

    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                # Normalize path for cross-platform JSON consistency
                relative_path = os.path.relpath(filepath, start=os.path.dirname(target_dir)).replace('\\', '/')
                manifest["execution_matrices"][relative_path] = hash_file(filepath)
                logging.info(f"Hashed: {relative_path}")

    with open(output_file, 'w') as f:
        json.dump(manifest, f, indent=2)
        
    logging.info(f"Cryptographic manifest serialized to {output_file}")
    logging.info("AETHERIS DEPLOYMENT LOCKED. No further AST modifications permitted.")

if __name__ == '__main__':
    # Target the local core directory and output to the root namespace
    target_namespace = os.path.abspath(os.path.join(os.path.dirname(__file__), 'core'))
    manifest_output = os.path.abspath(os.path.join(os.path.dirname(__file__), 'deployment_manifest.json'))
    
    generate_deployment_manifest(target_namespace, manifest_output)