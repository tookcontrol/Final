import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# --- Configuration ---
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
AES_KEY_SIZE_BYTES = 32  # AES-256
AES_MODE = modes.GCM # Using GCM for authenticated encryption

# --- File Names ---
MSG_FILE = "message.txt"
ENC_MSG_FILE = "encrypted_message.bin"
ENC_AES_KEY_FILE = "aes_key_encrypted.bin"
DEC_MSG_FILE = "decrypted_message.txt"
PUBLIC_KEY_FILE = "user_a_public.pem"
PRIVATE_KEY_FILE = "user_a_private.pem"

# --- User A: Generate RSA Key Pair ---
print("User A: Generating RSA key pair...")
private_key = rsa.generate_private_key(
    public_exponent=RSA_PUBLIC_EXPONENT,
    key_size=RSA_KEY_SIZE,
)
public_key = private_key.public_key()

# Save keys (optional, but good practice)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(), # No password for simplicity
)
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(PRIVATE_KEY_FILE, "wb") as f:
    f.write(pem_private)
print(f"User A: Private key saved to {PRIVATE_KEY_FILE}")

with open(PUBLIC_KEY_FILE, "wb") as f:
    f.write(pem_public)
print(f"User A: Public key saved to {PUBLIC_KEY_FILE} (Shared with User B)")

# --- User B: Encrypt Message ---
print("\nUser B: Starting encryption process...")

# 1. Create the message
message_content = b"This is a top secret message from User B to User A."
with open(MSG_FILE, "wb") as f:
    f.write(message_content)
print(f"User B: Secret message written to {MSG_FILE}")

# 2. Generate random AES key
aes_key = os.urandom(AES_KEY_SIZE_BYTES)
print(f"User B: Generated random {AES_KEY_SIZE_BYTES*8}-bit AES key.")

# 3. Encrypt message using AES-GCM
# GCM requires a nonce (IV). 12 bytes (96 bits) is recommended.
nonce = os.urandom(12)
cipher_aes = Cipher(algorithms.AES(aes_key), AES_MODE(nonce))
encryptor_aes = cipher_aes.encryptor()

# GCM provides authentication, associated data can be added if needed
# encryptor_aes.authenticate_additional_data(b"optional authenticated data")

ciphertext = encryptor_aes.update(message_content) + encryptor_aes.finalize()
# GCM includes the authentication tag automatically. Need nonce + tag + ciphertext
encrypted_message = nonce + encryptor_aes.tag + ciphertext

with open(ENC_MSG_FILE, "wb") as f:
    f.write(encrypted_message)
print(f"User B: Message encrypted with AES-GCM, saved to {ENC_MSG_FILE}")

# 4. Encrypt AES key using User A's public RSA key
# Load User A's public key (simulating User B receiving it)
with open(PUBLIC_KEY_FILE, "rb") as key_file:
    user_a_public_key = serialization.load_pem_public_key(key_file.read())

aes_key_encrypted = user_a_public_key.encrypt(
    aes_key,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

with open(ENC_AES_KEY_FILE, "wb") as f:
    f.write(aes_key_encrypted)
print(f"User B: AES key encrypted with RSA, saved to {ENC_AES_KEY_FILE}")
print("User B: Sending encrypted files to User A...")

# --- User A: Decrypt Message ---
print("\nUser A: Starting decryption process...")

# 1. Load own private RSA key
with open(PRIVATE_KEY_FILE, "rb") as key_file:
    user_a_private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None, # No password was set
    )

# 2. Decrypt AES key using private RSA key
with open(ENC_AES_KEY_FILE, "rb") as f:
    aes_key_encrypted_loaded = f.read()

decrypted_aes_key = user_a_private_key.decrypt(
    aes_key_encrypted_loaded,
    rsa_padding.OAEP(
        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print("User A: Decrypted AES key using RSA private key.")

# 3. Decrypt message using the decrypted AES key
with open(ENC_MSG_FILE, "rb") as f:
    encrypted_message_loaded = f.read()

# Extract nonce, tag, and ciphertext (order matters!)
nonce_loaded = encrypted_message_loaded[:12]
# GCM tag is typically 16 bytes
tag_loaded = encrypted_message_loaded[12:28]
ciphertext_loaded = encrypted_message_loaded[28:]

cipher_aes_decrypt = Cipher(
    algorithms.AES(decrypted_aes_key), AES_MODE(nonce_loaded, tag_loaded)
)
decryptor_aes = cipher_aes_decrypt.decryptor()

# If using associated data during encryption, authenticate it here too
# decryptor_aes.authenticate_additional_data(b"optional authenticated data")

try:
    decrypted_message = decryptor_aes.update(
        ciphertext_loaded
    ) + decryptor_aes.finalize()
    # finalize() checks the authentication tag in GCM
    with open(DEC_MSG_FILE, "wb") as f:
        f.write(decrypted_message)
    print(f"User A: Message decrypted successfully, saved to {DEC_MSG_FILE}")

    # Verification
    print("\nVerification:")
    print(f"Original message: {message_content}")
    print(f"Decrypted message: {decrypted_message}")
    if message_content == decrypted_message:
        print("Success: Decrypted message matches the original.")
    else:
        print("Error: Decrypted message does not match the original.")

except Exception as e:
    print(f"User A: Decryption failed! Error: {e}")
    print("This could be due to incorrect key, corrupted data, or failed integrity check (tag mismatch).")

