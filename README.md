# Goldwasser–Micali Cryptosystem

This project implements the **Goldwasser–Micali** public-key encryption algorithm — a probabilistic encryption scheme based on the hardness of computing quadratic residues modulo a composite number.

It includes:
- **Key generation** using two large primes
- **Probabilistic encryption** of binary-encoded messages
- **Decryption** using the Jacobi symbol
- **Optional HMAC-based digital signatures** for message authentication
- **Comprehensive unit tests** with `pytest`

## 🔒 Algorithm Overview

- **Encryption**: Each bit is encrypted using a random quadratic residue or non-residue mod `n = p * q`.
- **Decryption**: The receiver uses the Jacobi symbol modulo `p` or `q` to recover each bit.
- **Security**: Based on the quadratic residuosity problem (assumed hard).

## 🧪 Running the Tests

1. Install `pytest` if you haven't already:
   ```bash
   pip install pytest

