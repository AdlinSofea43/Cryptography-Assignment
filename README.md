# Hybrid Encryption Implementation

## Overview
This Python script implements multiple encryption algorithms, combining classical and modern cryptographic techniques. It includes:
- **Playfair Cipher** (Classical Substitution Cipher)
- **Rail Fence Cipher** (Classical Transposition Cipher)
- **AES Encryption** (Modern Symmetric Encryption)
- **RSA Encryption** (Asymmetric Key Exchange)
- **Execution Time Measurement** for each encryption and decryption process

## Features
- Encrypt and decrypt text using Playfair and Rail Fence ciphers.
- Securely encrypt text using AES with a secret key.
- Use RSA to securely exchange the AES key.
- Measure execution time for performance analysis.

## Requirements
Ensure you have the following dependencies installed before running the script:

```sh
pip install pycryptodome numpy

