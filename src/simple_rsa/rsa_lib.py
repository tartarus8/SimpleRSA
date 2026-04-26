import random
import math
import json
import base64
from typing import Tuple, List

class PublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e

    def export_key(self, filename: str):
        with open(filename, 'w') as f:
            json.dump({"n": self.n, "e": self.e}, f)

    @classmethod
    def import_key(cls, filename: str) -> 'PublicKey':
        with open(filename, 'r') as f:
            data = json.load(f)
            return cls(data["n"], data["e"])

class PrivateKey:
    def __init__(self, n: int, d: int):
        self.n = n
        self.d = d

    def export_key(self, filename: str):
        with open(filename, 'w') as f:
            json.dump({"n": self.n, "d": self.d}, f)

    @classmethod
    def import_key(cls, filename: str) -> 'PrivateKey':
        with open(filename, 'r') as f:
            data = json.load(f)
            return cls(data["n"], data["d"])


def _miller_rabin(n: int, k: int = 40) -> bool:
    # Standard Miller-Rabin primality test
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits: int) -> int:
    while True:
        # Generate random bits and ensure the number is odd and exactly 'bits' long
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if _miller_rabin(p):
            return p

def generate_keys(key_size_bits: int = 2048) -> Tuple[PublicKey, PrivateKey]:
    # Generates an RSA Keypair. Standard secure size is 2048 bits
    prime_size = key_size_bits // 2
    p = _generate_prime(prime_size)
    q = _generate_prime(prime_size)

    while p == q:
        q = _generate_prime(prime_size)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if math.gcd(e, phi) != 1:
        e = random.randrange(3, phi - 1, 2)
        while math.gcd(e, phi) != 1:
            e = random.randrange(3, phi - 1, 2)

    d = pow(e, -1, phi)

    return PublicKey(n, e), PrivateKey(n, d)

def encrypt(message: str, public_key: PublicKey) -> str:
    # Encrypts a string message into a safe, copy-pasteable Base64 string
    # Automatically chunks large messages
    # Max bytes per block = key bytes minus 2 (to leave room for \x80 prefix)
    key_bytes = public_key.n.bit_length() // 8
    max_block_size = key_bytes - 2

    msg_bytes = message.encode('utf-8')
    encrypted_blocks =[]

    for i in range(0, len(msg_bytes), max_block_size):
        block = msg_bytes[i:i+max_block_size]
        # Prepend '\x80' to prevent Python from dropping leading zeros on int conversion
        block = b'\x80' + block

        m = int.from_bytes(block, byteorder='big')
        c = pow(m, public_key.e, public_key.n)
        encrypted_blocks.append(c)

    json_data = json.dumps(encrypted_blocks).encode('utf-8')
    return base64.b64encode(json_data).decode('utf-8')

def decrypt(ciphertext: str, private_key: PrivateKey) -> str:
    try:
        json_data = base64.b64decode(ciphertext).decode('utf-8')
        encrypted_blocks = json.loads(json_data)
    except Exception:
        raise ValueError("Invalid ciphertext format.")

    decrypted_bytes = bytearray()

    for c in encrypted_blocks:
        m = pow(c, private_key.d, private_key.n)
        block = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')

        # Remove '\x80' prefix and append to total
        decrypted_bytes.extend(block[1:])

    return decrypted_bytes.decode('utf-8')
