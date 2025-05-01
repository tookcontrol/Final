import hashlib
import json
import os

HASHES_FILE = "hashes.json"


def compute_hashes(filepath):
    """Computes MD5, SHA1, and SHA256 hashes for a given file."""
    hashes = {}
    try:
        # Read file in binary mode for consistent hashing
        with open(filepath, "rb") as f:
            file_content = f.read()
            hashes["md5"] = hashlib.md5(file_content).hexdigest()
            hashes["sha1"] = hashlib.sha1(file_content).hexdigest()
            hashes["sha256"] = hashlib.sha256(file_content).hexdigest()
        return hashes
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except Exception as e:
        print(f"Error computing hashes for {filepath}: {e}")
        return None


def store_hashes(filename, hashes_to_store, json_file=HASHES_FILE):
    """Stores the computed hashes in a JSON file."""
    all_hashes = {}
    if os.path.exists(json_file):
        try:
            with open(json_file, "r") as f:
                all_hashes = json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: Could not decode existing {json_file}. Starting fresh.")
        except Exception as e:
            print(f"Error reading {json_file}: {e}. Starting fresh.")

    all_hashes[filename] = hashes_to_store

    try:
        with open(json_file, "w") as f:
            json.dump(all_hashes, f, indent=4)
        print(f"Stored hashes for '{filename}' in {json_file}")
    except Exception as e:
        print(f"Error writing to {json_file}: {e}")


def verify_integrity(filename, json_file=HASHES_FILE):
    """Verifies the integrity of a file against stored hashes."""
    print(f"\n--- Verifying integrity of '{filename}' ---")
    if not os.path.exists(filename):
        print("Result: FAILED (File does not exist)")
        return False

    if not os.path.exists(json_file):
        print(f"Result: FAILED (Hashes file '{json_file}' not found)")
        return False

    # Load stored hashes
    stored_hashes_for_all = {}
    try:
        with open(json_file, "r") as f:
            stored_hashes_for_all = json.load(f)
    except Exception as e:
        print(f"Result: FAILED (Error loading hashes file: {e})")
        return False

    if filename not in stored_hashes_for_all:
        print(f"Result: FAILED (No stored hashes found for '{filename}')")
        return False

    stored_hashes = stored_hashes_for_all[filename]

    # Compute current hashes
    current_hashes = compute_hashes(filename)
    if current_hashes is None:
        print("Result: FAILED (Could not compute current hashes)")
        return False

    # Compare hashes
    mismatches = []
    for algo in ["md5", "sha1", "sha256"]:
        if algo not in stored_hashes or algo not in current_hashes:
            print(f"Warning: Hash algorithm '{algo}' missing in stored or current hashes.")
            mismatches.append(algo) # Treat missing hash as mismatch
        elif stored_hashes[algo] != current_hashes[algo]:
            mismatches.append(algo)
            print(f"Mismatch found for {algo.upper()}:")
            print(f"  Stored:   {stored_hashes[algo]}")
            print(f"  Computed: {current_hashes[algo]}")

    if not mismatches:
        print("Result: PASSED (All computed hashes match stored hashes)")
        return True
    else:
        print(f"Result: FAILED (Hash mismatch detected for: {', '.join(mismatches)})")
        return False


# --- Main Execution ---
if __name__ == "__main__":
    # 1. Create original file
    original_filename = "original.txt"
    tampered_filename = "tampered.txt"
    original_content = b"This is the original file content.\nIt should remain unchanged."
    tampered_content = b"This is the original file content.\nIt should remain unchaged." # Typo!

    with open(original_filename, "wb") as f:
        f.write(original_content)
    print(f"Created '{original_filename}'")

    # 2. Compute and store hashes for the original file
    original_hashes = compute_hashes(original_filename)
    if original_hashes:
        store_hashes(original_filename, original_hashes)

    # 3. Create tampered file
    with open(tampered_filename, "wb") as f:
        f.write(tampered_content)
    print(f"Created '{tampered_filename}' (with a slight modification)")

    # 4. Verify original file (should pass)
    verify_integrity(original_filename)

    # 5. Verify tampered file (should fail)
    verify_integrity(tampered_filename)

    # 6. Verify non-existent file (should fail)
    verify_integrity("non_existent_file.txt")

