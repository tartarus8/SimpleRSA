# SimpleRSA
RSA impementation for casual tasks

## Features
* **Zero Dependencies:** Uses only Python standard libraries. No C-compilers or external packages required.
* **Automatic Chunking:** Encrypt messages of *any* length. The library automatically splits massive texts into block sizes appropriate for your key.
* **Safe Encoding:** Outputs ciphertexts as JSON-bundled Base64 strings, preventing encoding errors during copy-pasting.

## Installation
**Install via pip:**
If you published this to PyPI:
```bash
pip install simple-rsa
```

**Install locally from source:**
```bash
git clone https://github.com/yourusername/simple-rsa.git
cd simple-rsa
pip install .
```
## Quickstart

### 1.Generating Keys
Generate a public/private keypair. The standard is `2048` bits.

```python
from simple_rsa import generate_keys

# Generate keys (returns PublicKey and PrivateKey objects)
public_key, private_key = generate_keys(key_size_bits=2048)
```

### 2. Encrypting & Decrypting
You can encrypt strings of any size. The library handles the math and chunking behind the scenes.

```python
from simple_rsa import encrypt, decrypt

secret_message = "Hello! This is a highly classified message."

# Encrypt (Outputs a Base64 string)
ciphertext = encrypt(secret_message, public_key)
print(f"Encrypted: {ciphertext}")

# Decrypt
decrypted_message = decrypt(ciphertext, private_key)
print(f"Decrypted: {decrypted_message}")
```

### 3. Saving & Loading Keys
Easily export your keys to disk as JSON files to use later.

```python
from simple_rsa import PublicKey, PrivateKey

# Save to disk
public_key.export_key("public_key.json")
private_key.export_key("private_key.json")

# Load from disk
loaded_pub = PublicKey.import_key("public_key.json")
loaded_priv = PrivateKey.import_key("private_key.json")
```

## Security Disclaimer

This library implements **Unpadded Textbook RSA** with basic block chunking. It is highly effective for:
* Educational purposes and learning cryptography.
* Capture The Flag (CTF) challenges.
* Internal lightweight tooling or hobby projects.

**However, it is NOT recommended for mission-critical, state-actor-level production environments.** Because it does not use randomized padding, identical blocks of plain text will yield identical blocks of ciphertext. For bank-level production systems, use the standard `cryptography` library.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
```
