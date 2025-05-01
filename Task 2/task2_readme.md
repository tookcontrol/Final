# Task 2: Secure File Exchange - Explanation & Comparison

This task demonstrates a hybrid encryption protocol for secure file exchange between Alice and Bob, including an integrity check.

## Encryption/Decryption Flow

1.  **Key Generation (Bob)**: Bob generates an RSA key pair and saves them in PEM format (`public.pem`, `private.pem`). He shares `public.pem` with Alice.
2.  **File Preparation (Alice)**: Alice creates the plaintext file (`alice_message.txt`) and calculates its SHA-256 hash for later verification.
3.  **Symmetric Encryption (Alice)**:
    *   Alice generates a random AES-256 key and a random Initialization Vector (IV).
    *   She encrypts `alice_message.txt` using AES-256 in CBC (Cipher Block Chaining) mode with the generated key and IV. PKCS7 padding is applied before encryption.
    *   The IV is prepended to the resulting ciphertext. The combined data (IV + ciphertext) is saved as `encrypted_file.bin`.
4.  **Asymmetric Encryption (Alice)**: Alice encrypts the *AES key* (not the IV) using Bob's public RSA key (with OAEP padding) and saves it as `aes_key_encrypted.bin`.
5.  **Transmission (Alice to Bob)**: Alice sends `encrypted_file.bin` and `aes_key_encrypted.bin` to Bob.
6.  **Asymmetric Decryption (Bob)**: Bob uses his *private RSA key* to decrypt `aes_key_encrypted.bin`, recovering the AES key.
7.  **Symmetric Decryption (Bob)**:
    *   Bob reads `encrypted_file.bin`. He separates the IV (first 16 bytes) from the ciphertext.
    *   He decrypts the ciphertext using the recovered AES key and the IV in AES-256-CBC mode.
    *   He removes the PKCS7 padding from the decrypted data to get the original plaintext.
    *   The result is saved as `decrypted_message.txt`.
8.  **Integrity Verification (Bob)**: Bob calculates the SHA-256 hash of the `decrypted_message.txt` and compares it to the original hash provided by Alice (or calculated beforehand if Alice shared it). A match confirms the file's integrity.

## Comparison: AES vs. RSA

| Feature      | AES (Advanced Encryption Standard)                     | RSA (Rivest–Shamir–Adleman)                                  |
| :----------- | :----------------------------------------------------- | :----------------------------------------------------------- |
| **Type**     | Symmetric-key algorithm                                | Asymmetric-key algorithm                                     |
| **Keys**     | Uses the *same* secret key for encryption & decryption | Uses a *public key* for encryption, *private key* for decryption |
| **Speed**    | Very fast (hardware acceleration common)               | Significantly slower than AES                                |
| **Use Case** | Encrypting bulk data (files, network traffic, etc.)    | Key exchange, digital signatures, encrypting small data (like symmetric keys) |
| **Security** | Secure when used with strong keys (128, 192, 256 bits) and proper modes (e.g., GCM, CBC). Security relies on resistance to cryptanalysis. | Secure with large key sizes (2048+ bits) and proper padding (e.g., OAEP). Security relies on the difficulty of factoring large numbers. |
| **Key Mgmt** | Key distribution can be challenging (how to share the secret key securely?) | Simpler key distribution (public key can be shared openly), but requires managing key pairs. |

**Hybrid Approach Benefit**: Combines the speed of AES for data encryption with the secure key exchange capability of RSA, leveraging the strengths of both.
