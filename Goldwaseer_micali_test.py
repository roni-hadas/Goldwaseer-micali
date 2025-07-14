import random
import string
import pytest
from itertools import islice
from Goldwaseer_micali_main import (
    generate_keypair,
    encrypt_string,
    decrypt_cipher,
    encode_ascii_string,
    decode_ascii_number,
    jacobi_symbol,
    sign_message,
    verify_signature
)

def self_test_one(prime_size=6, seed=0):
    random.seed(seed)
    keys = generate_keypair(prime_size)
    msg = ''.join(random.choices(string.ascii_letters + ' ,.!?', k=random.randint(5, 25)))
    ct  = encrypt_string(msg, keys['pub'])
    out = decrypt_cipher(ct, keys['priv'])
    assert out == msg
    return True

@pytest.mark.parametrize("seed", range(200))
@pytest.mark.parametrize("prime_size", [6, 8, 12])
def test_round_trip(seed, prime_size):
    random.seed(seed)
    keys = generate_keypair(prime_size)
    msg_len = random.randint(5, 25)
    alphabet = string.ascii_letters + " ,.!?"
    msg = "".join(random.choices(alphabet, k=msg_len))
    ct = encrypt_string(msg, keys["pub"])
    out = decrypt_cipher(ct, keys["priv"])
    assert out == msg

def test_semantic_security():
    random.seed(42)
    keys = generate_keypair(10)
    msg = "Hello, World!"
    ct1 = encrypt_string(msg, keys["pub"])
    ct2 = encrypt_string(msg, keys["pub"])
    assert ct1 != ct2, "ciphertexts matched – encryption may be deterministic"

def test_decrypt_with_wrong_key():
    random.seed(1337)
    msg = "Goldwasser & Micali"
    k1 = generate_keypair(8)
    k2 = generate_keypair(8)
    ct = encrypt_string(msg, k1["pub"])
    out = decrypt_cipher(ct, k2["priv"])
    assert out != msg

@pytest.mark.parametrize("word", ["A", "abcXYZ!?.,", "hello world", "R264rjk", "Final_Project_Crypto"])
def test_encode_decode(word):
    binary_str = f"{encode_ascii_string(word):b}"
    decoded = decode_ascii_number(int(binary_str, 2))
    assert decoded == word

@pytest.mark.parametrize("p", [3, 5, 7, 11, 13])
@pytest.mark.parametrize("a", [1, 2, 3, 4, 5])
def test_jacobi_values(p, a):
    j = jacobi_symbol(a, p)
    assert j in {-1, 0, 1}
    b = (a + 1) % p or 2
    assert jacobi_symbol(a, p) * jacobi_symbol(b, p) == jacobi_symbol((a * b) % p, p)

def big_random_messages():
    alphabet = string.ascii_letters + string.digits + " ,.!?"
    for n in islice(range(20), 20):
        yield "".join(random.choices(alphabet, k=50 * n + 1))

@pytest.mark.parametrize("msg", big_random_messages())
def test_large_messages(msg):
    random.seed(len(msg))
    keys = generate_keypair(12)
    ct = encrypt_string(msg, keys["pub"])
    out = decrypt_cipher(ct, keys["priv"])
    assert out == msg

def test_signed_encrypted_communication():
    # 1. Alice wants to send a message securely
    secret_key = b'shared_key'  # shared secret between Alice and Bob
    message = "Meet me at the park at noon."

    # 2. Alice generates keypair and encrypts the message
    keypair = generate_keypair(10)
    ciphertext = encrypt_string(message, keypair['pub'])

    # 3. Alice signs the original (plaintext) message
    signature = sign_message(secret_key, message)

    # === Transmission happens here (ciphertext + signature sent to Bob) ===

    # 4. Bob decrypts
    decrypted = decrypt_cipher(ciphertext, keypair['priv'])

    # 5. Bob verifies the signature
    assert verify_signature(secret_key, decrypted, signature), "Signature verification failed"

    # 6. Confirm that the decrypted message matches
    assert decrypted == message, "Decrypted message mismatch"

