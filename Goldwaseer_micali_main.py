import hashlib
import hmac
from random import randint
from functools import reduce


# -------------------- PRIME CHECKING --------------------

def miller_rabin_test(candidate: int, iterations: int) -> bool:
    """Return True if candidate is likely a prime number."""
    assert candidate % 2 == 1 and candidate > 4 and iterations >= 1

    r = candidate - 1
    s = 0
    while r % 2 == 0:
        s += 1
        r //= 2

    for _ in range(iterations):
        base = randint(2, candidate - 2)
        y = pow(base, r, candidate)

        if y != 1 and y != candidate - 1:
            for _ in range(s - 1):
                y = pow(y, 2, candidate)
                if y == 1:
                    return False
                if y == candidate - 1:
                    break
            else:
                return False
    return True


def is_probable_prime(n: int) -> bool:
    if n in {2, 3}:
        return True
    if n % 2 == 0:
        return False
    return miller_rabin_test(n, 10)


def nearest_prime_to(n: int) -> int:
    if is_probable_prime(n):
        return n

    n += 1 if n % 2 == 0 else 0
    lower = n - 2

    while True:
        if is_probable_prime(n):
            return n
        if is_probable_prime(lower):
            return lower
        n += 2
        lower -= 2


def generate_large_prime(digits: int) -> int:
    number = randint(0, 9)
    for d in range(1, digits):
        number += randint(0, 9) * 10**d
    return nearest_prime_to(number)


# -------------------- MATH UTILS --------------------

def extended_euclidean(a: int, b: int):
    """Return (gcd, x, y) such that a*x + b*y = gcd."""
    x = [1, 0]
    y = [0, 1]
    sign = 1

    while b:
        q, r = divmod(a, b)
        a, b = b, r
        x[1], x[0] = q * x[1] + x[0], x[1]
        y[1], y[0] = q * y[1] + y[0], y[1]
        sign = -sign

    return a, sign * x[0], -sign * y[0]


def chinese_remainder_theorem(remainders, mod_list):
    modulus = reduce(lambda a, b: a * b, mod_list)
    result = 0

    for ai, mi in zip(remainders, mod_list):
        Mi = modulus // mi
        _, inverse, _ = extended_euclidean(Mi, mi)
        result = (result + ai * inverse * Mi) % modulus

    return result


def jacobi_symbol(a: int, n: int) -> int:
    if a == 0:
        return 0
    if a == 1:
        return 1

    a1 = a
    e = 0
    while a1 % 2 == 0:
        e += 1
        a1 //= 2

    s = 1
    if e % 2 != 0 and n % 8 in {3, 5}:
        s = -1

    if n % 4 == 3 and a1 % 4 == 3:
        s *= -1

    return s if a1 == 1 else s * jacobi_symbol(n % a1, a1)


def find_non_residue(mod: int) -> int:
    while True:
        a = randint(1, mod - 1)
        if jacobi_symbol(a, mod) == -1:
            return a


# -------------------- KEY GENERATION --------------------

def generate_pseudo_square(p: int, q: int) -> int:
    res_p = find_non_residue(p)
    res_q = find_non_residue(q)
    return chinese_remainder_theorem([res_p, res_q], [p, q])


def generate_keypair(prime_digits: int = 6):
    p = generate_large_prime(prime_digits)
    q = generate_large_prime(prime_digits)
    while q == p:
        q = generate_large_prime(prime_digits)

    n = p * q
    y = generate_pseudo_square(p, q)

    return {'pub': (n, y), 'priv': (p, q)}


# -------------------- ENCRYPTION / DECRYPTION --------------------

def encode_ascii_string(s: str) -> int:
    encoded = s.encode('ascii', 'ignore')
    if not encoded:
        raise ValueError("Only non-empty ASCII strings are supported")
    return int(''.join(f"{c:03d}" for c in encoded))


def decode_ascii_number(number: int) -> str:
    s = str(number)
    pad = (3 - len(s) % 3) % 3
    s = "0" * pad + s

    return ''.join(chr(int(s[i:i + 3])) for i in range(0, len(s), 3))


def encrypt_string(message: str, pub_key) -> list[int]:
    n, y = pub_key
    bits = [bit == "1" for bit in f"{encode_ascii_string(message):b}"]

    def encrypt_bit(bit_val: bool):
        r = randint(0, n - 1)
        return (y * pow(r, 2, n)) % n if bit_val else pow(r, 2, n)

    return [encrypt_bit(b) for b in bits]


def decrypt_cipher(cipher: list[int], priv_key) -> str:
    p, _ = priv_key

    def decrypt_bit(c: int) -> bool:
        return jacobi_symbol(c, p) != 1

    bit_str = ''.join('1' if decrypt_bit(c) else '0' for c in cipher)
    return decode_ascii_number(int(bit_str, 2))

def sign_message(secret_key: bytes, message: str) -> str:
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def verify_signature(secret_key: bytes, message: str, signature: str) -> bool:
    return hmac.compare_digest(
        hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest(),
        signature
    )
