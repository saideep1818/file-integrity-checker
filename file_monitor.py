
import os
import hashlib
import json
import time

HASH_RECORD_FILE = 'file_hashes.json'


def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None


def scan_directory(directory):
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            file_hashes[full_path] = calculate_hash(full_path)
    return file_hashes


def save_hashes(hashes):
    with open(HASH_RECORD_FILE, 'w') as f:
        json.dump(hashes, f, indent=4)


def load_hashes():
    if not os.path.exists(HASH_RECORD_FILE):
        return {}
    with open(HASH_RECORD_FILE, 'r') as f:
        return json.load(f)


def compare_hashes(old_hashes, new_hashes):
    old_files = set(old_hashes.keys())
    new_files = set(new_hashes.keys())

    added = new_files - old_files
    deleted = old_files - new_files
    modified = [file for file in old_files & new_files if old_hashes[file] != new_hashes[file]]

    return added, deleted, modified


def main():
    directory = input("Enter the directory to monitor: ").strip()
    print("Scanning and calculating file hashes...")

    new_hashes = scan_directory(directory)
    old_hashes = load_hashes()

    added, deleted, modified = compare_hashes(old_hashes, new_hashes)

    if added or deleted or modified:
        print("\nChanges Detected:")
        if added:
            print(f"\n🟢 Added Files:\n" + "\n".join(added))
        if deleted:
            print(f"\n🔴 Deleted Files:\n" + "\n".join(deleted))
        if modified:
            print(f"\n🟡 Modified Files:\n" + "\n".join(modified))
    else:
        print("\n✅ No changes detected.")

    save_hashes(new_hashes)


if __name__ == "__main__":
    main()
