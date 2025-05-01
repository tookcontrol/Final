import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# --- Configuration ---
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE_BYTES = 32  # AES-256
AES_BLOCK_SIZE_BYTES = 16 # 128 bits for AES
AES_MODE = modes.CBC # Using CBC as IV is explicitly mentioned

# --- File Names ---
ALICE_MSG_FILE = "alice_message.txt"
ENC_FILE = "encrypted_file.bin"
ENC_AES_KEY_FILE = "aes_key_encrypted.bin"
DEC_MSG_FILE = "decrypted_message.txt"
BOB_PUBLIC_KEY_FILE = "public.pem"
BOB_PRIVATE_KEY_FILE = "private.pem"

# --- Bob: Generate RSA Key Pair ---
print("Bob: Generating RSA key pair...")
bob_private_key = rsa.generate_private_key(
    public_exponent=RSA_PUBLIC_EXPONENT,
    key_size=RSA_KEY_SIZE,
)
bob_public_key = bob_private_key.public_key()

# Save keys in PEM format
pem_bob_private = bob_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(), # No password
)
pem_bob_public = bob_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(BOB_PRIVATE_KEY_FILE, "wb") as f:
    f.write(pem_bob_private)
print(f"Bob: Private key saved to {BOB_PRIVATE_KEY_FILE}")

with open(BOB_PUBLIC_KEY_FILE, "wb") as f:
    f.write(pem_bob_public)
print(f"Bob: Public key saved to {BOB_PUBLIC_KEY_FILE} (Shared with Alice)")

# --- Alice: Encrypt File ---
print("\nAlice: Starting encryption process...")

# 1. Create plaintext file
alice_message_content = b"This is a secret file from Alice for Bob's eyes only."
with open(ALICE_MSG_FILE, "wb") as f:
    f.write(alice_message_content)
print(f"Alice: Secret file created: {ALICE_MSG_FILE}")

# Calculate original hash for later verification
original_hash = hashlib.sha256(alice_message_content).hexdigest()
print(f"Alice: SHA-256 hash of original file: {original_hash}")

# 2. Generate random AES key and IV
aes_key = os.urandom(AES_KEY_SIZE_BYTES)
iv = os.urandom(AES_BLOCK_SIZE_BYTES)
print(f"Alice: Generated random AES key and IV.")

# 3. Encrypt the file using AES-CBC
# CBC requires padding to block size
padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(alice_message_content) + padder.finalize()

cipher_aes = Cipher(algorithms.AES(aes_key), AES_MODE(iv))
encryptor_aes = cipher_aes.encryptor()
ciphertext = encryptor_aes.update(padded_data) + encryptor_aes.finalize()

# Prepend IV to the ciphertext for transmission
encrypted_data = iv + ciphertext
with open(ENC_FILE, "wb") as f:
    f.write(encrypted_data)
print(f"Alice: File encrypted with AES-CBC (IV prepended), saved to {ENC_FILE}")

# 4. Encrypt the AES key using Bob's public RSA key
# Load Bob's public key
with open(BOB_PUBLIC_KEY_FILE, "rb") as key_file:
    bob_public_key_loaded = serialization.load_pem_public_key(key_file.read())

aes_key_encrypted = bob_public_key_loaded.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

with open(ENC_AES_KEY_FILE, "wb") as f:
    f.write(aes_key_encrypted)
print(f"Alice: AES key encrypted with RSA, saved to {ENC_AES_KEY_FILE}")
print("Alice: Sending encrypted files to Bob...")

# --- Bob: Decrypt File and Verify Integrity ---
print("\nBob: Starting decryption and verification...")

# 1. Load own private RSA key
with open(BOB_PRIVATE_KEY_FILE, "rb") as key_file:
    bob_private_key_loaded = serialization.load_pem_private_key(
        key_file.read(),
        password=None, # No password
    )

# 2. Decrypt AES key using private RSA key
with open(ENC_AES_KEY_FILE, "rb") as f:
    aes_key_encrypted_loaded = f.read()

decrypted_aes_key = bob_private_key_loaded.decrypt(
    aes_key_encrypted_loaded,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print("Bob: Decrypted AES key using RSA private key.")

# 3. Decrypt the file using the decrypted AES key and IV
with open(ENC_FILE, "rb") as f:
    encrypted_data_loaded = f.read()

# Extract IV (first block) and ciphertext
iv_loaded = encrypted_data_loaded[:AES_BLOCK_SIZE_BYTES]
ciphertext_loaded = encrypted_data_loaded[AES_BLOCK_SIZE_BYTES:]

cipher_aes_decrypt = Cipher(algorithms.AES(decrypted_aes_key), AES_MODE(iv_loaded))
decryptor_aes = cipher_aes_decrypt.decryptor()
padded_decrypted_message = decryptor_aes.update(ciphertext_loaded) + decryptor_aes.finalize()

# Remove padding
unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
decrypted_message = unpadder.update(padded_decrypted_message) + unpadder.finalize()

with open(DEC_MSG_FILE, "wb") as f:
    f.write(decrypted_message)
print(f"Bob: File decrypted successfully, saved to {DEC_MSG_FILE}")

# 4. Compute SHA-256 hash of decrypted file and compare
decrypted_hash = hashlib.sha256(decrypted_message).hexdigest()
print(f"Bob: SHA-256 hash of decrypted file: {decrypted_hash}")
print(f"Alice's original hash:             {original_hash}")

if decrypted_hash == original_hash:
    print("Integrity Check PASSED: Hashes match.")
else:
    print("Integrity Check FAILED: Hashes do not match! File may be corrupt or tampered with.")

