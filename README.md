# Guillou - Quisquater Digital Signature in Z\*<sub>n</sub>

Java implementation of the **Guillou–Quisquater** (GQ) identity-based digital signature scheme, together with a demonstration of the protocol and a comparative benchmark against **RSA**.

![Java](https://img.shields.io/badge/Java-11%2B-orange?logo=openjdk&logoColor=white)
![License](https://img.shields.io/badge/license-Academic-blue)
![Status](https://img.shields.io/badge/status-completed-brightgreen)

---

## Table of Contents

1. [File description](#1-file-description)
2. [System requirements](#2-system-requirements)
3. [Compilation](#3-compilation)
4. [Running](#4-running)
5. [Expected results](#5-expected-results)
6. [Code structure](#6-code-structure)

---

## 1. File description

The project contains **3 Java source files** in the [`Implementation/`](Implementation/) directory:

| File                                                  | Role                                                                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| [`GQSignature.java`](Implementation/GQSignature.java) | Main implementation of the GQ algorithm (parameter generation, certification, signing, verification) |
| [`GQDemo.java`](Implementation/GQDemo.java)           | Complete demonstration with two users (Alice and Bob). Includes integrity and authenticity tests     |
| [`GQBenchmark.java`](Implementation/GQBenchmark.java) | Comparative performance measurements **GQ vs RSA**. Tests 1024- and 2048-bit keys                    |

In addition, the project's IEEE paper is located in [`Docs/`](Docs/):
[`GQ_Referat_IEEE.pdf`](Docs/GQ_Referat_IEEE.pdf).

---

## 2. System requirements

- **Java Development Kit (JDK) version 11 or newer**
  _(the code uses `String.repeat()` and `BigInteger.TWO`, which are not available in Java 8)_

Check the version:

```bash
java -version
javac -version
```

If `javac` is not available, install the full JDK:

| System                | Installation                                                  |
| --------------------- | ------------------------------------------------------------- |
| Windows               | Download from [adoptium.net](https://adoptium.net/) or Oracle |
| Linux (Ubuntu/Debian) | `sudo apt install default-jdk`                                |
| macOS                 | `brew install openjdk`                                        |

---

## 3. Compilation

Open a terminal in the [`Implementation/`](Implementation/) directory and run:

```bash
javac -encoding UTF-8 *.java
```

After compilation, the following `.class` files will appear:

- `GQSignature.class`
- `GQSignature$GQSignatureData.class` _(inner class holding the signature data)_
- `GQDemo.class`
- `GQBenchmark.class`

> **Note:** The `.class` files are excluded from the repository via [`.gitignore`](.gitignore).

---

## 4. Running

### A) Functionality demonstration

```bash
java GQDemo
```

The demo uses a **1024-bit** modulus and a **160-bit** security parameter `k`. It goes through 9 steps:

1. System parameter generation by the Certification Authority (`n`, `v`, `k`)
2. Registration of users Alice and Bob (certificate generation)
3. Distribution of the public parameters to the users
4. Alice signs a message
5. Bob verifies Alice's signature (must be **VALID**)
6. Integrity test with a tampered message (must be **INVALID**)
7. Authenticity test with a forged identity (must be **INVALID**)
8. Bob signs his own message
9. Alice verifies Bob's signature (must be **VALID**)

Finally, statistics about the modulus, certificate and signature sizes are printed.

### B) Benchmark — GQ vs RSA performance comparison

```bash
java GQBenchmark
```

For each key size (**1024** and **2048** bits) it measures, after a JVM warmup, the average and total time over **100 iterations** for:

- **GQ**: system setup, certificate generation, signing, verification
- **RSA Signature** (`SHA256withRSA`, PKCS#1 v1.5): key generation, signing, verification
- **RSA Encryption/Decryption** (`RSA/ECB/PKCS1Padding`): key generation, encryption, decryption

All output uses plain ASCII, so it renders correctly in any terminal (including Windows `cmd`).

---

## 5. Expected results

### A) When running `GQDemo`

Real output from one run (Windows 10, JDK 25):

```text
=== GUILLOU-QUISQUATER SCHEME DEMONSTRATION ===

Step 1: SYSTEM SETUP (Certification Authority)
------------------------------------------------------------
Generated public parameters:
  n (modulus): 1023 bits
  v (public exponent): 65537
  k (security parameter): 160

Step 2: USER REGISTRATION
------------------------------------------------------------
Generating user certificates...
  Alice (alice@company.com):
    Certificate: 1022 bits
  Bob (bob@company.com):
    Certificate: 1021 bits

Step 3: PUBLIC PARAMETER DISTRIBUTION
------------------------------------------------------------
Alice and Bob have received the public parameters (n, v, k)

Step 4: MESSAGE SIGNING (Alice)
------------------------------------------------------------
Message: "Contract: Transfer of 1000 EUR to Bob"

Generated signature:
  Challenge (d): 156 bits
  Response (y): 1023 bits
  Identity: alice@company.com

Step 5: SIGNATURE VERIFICATION (Bob verifies Alice's signature)
------------------------------------------------------------
Verification result: [OK] VALID

Step 6: INTEGRITY TEST - Tampered Message
------------------------------------------------------------
Tampered message: "Contract: Transfer of 9000 EUR to Bob"
Verification result: [FAIL] INVALID (as expected)

Step 7: AUTHENTICITY TEST - Forged Identity
------------------------------------------------------------
Alice's signature with Bob's identity (forgery)
Verification result: [FAIL] INVALID (as expected)

Step 8: MESSAGE SIGNING (Bob)
------------------------------------------------------------
Message: "I confirm receipt of 1000 EUR from Alice"

Signature generated by Bob
  Challenge (d): 160 bits
  Response (y): 1023 bits

Step 9: SIGNATURE VERIFICATION (Alice verifies Bob's signature)
------------------------------------------------------------
Verification result: [OK] VALID

=== STATISTICS ===
------------------------------------------------------------
Modulus size (n): 1024 bits
Certificate size: 1022 bits
Signature size: ~147 bytes

All tests completed successfully!
```

> The exact bit lengths of `n`, the certificates and `y` may vary by a bit or two between runs, because the primes `p` and `q` are generated randomly. The verification results (VALID / INVALID / INVALID / VALID) are always the same.

### B) When running `GQBenchmark`

Real output from one run (Windows 10, JDK 25; timings vary by machine and between runs):

```text
=== GUILLOU-QUISQUATER SCHEME vs RSA BENCHMARK ===

--- Key size: 1024 bits ---

GUILLOU-QUISQUATER:
  System setup:              240.000 ms
  Certificate generation:      2.765 ms
  Sign (average):              1.373 ms
  Verify (average):            1.967 ms
  Sign total (100):          137.273 ms
  Verify total (100):        196.718 ms
  Verification valid:     YES
  Signature size:         147 bytes

RSA SIGNATURE (PKCS#1 v1.5 with SHA-256):
  Key generation:             44.103 ms
  Sign (average):              1.011 ms
  Verify (average):            0.100 ms
  Sign total (100):          101.116 ms
  Verify total (100):         10.007 ms
  Verification valid:     YES
  Signature size:         128 bytes

RSA ENCRYPTION/DECRYPTION (PKCS#1 v1.5):
  Key generation:             33.454 ms
  Encrypt (average):           0.049 ms
  Decrypt (average):           0.648 ms
  Encrypt total (100):         4.935 ms
  Decrypt total (100):        64.750 ms

======================================================================

--- Key size: 2048 bits ---

GUILLOU-QUISQUATER:
  System setup:              311.923 ms
  Certificate generation:      9.731 ms
  Sign (average):              1.461 ms
  Verify (average):            1.893 ms
  Sign total (100):          146.125 ms
  Verify total (100):        189.335 ms
  Verification valid:     YES
  Signature size:         275 bytes

RSA SIGNATURE (PKCS#1 v1.5 with SHA-256):
  Key generation:            276.438 ms
  Sign (average):              2.127 ms
  Verify (average):            0.107 ms
  Sign total (100):          212.713 ms
  Verify total (100):         10.669 ms
  Verification valid:     YES
  Signature size:         256 bytes

RSA ENCRYPTION/DECRYPTION (PKCS#1 v1.5):
  Key generation:            139.894 ms
  Encrypt (average):           0.100 ms
  Decrypt (average):           2.554 ms
  Encrypt total (100):        10.005 ms
  Decrypt total (100):       255.403 ms

======================================================================
```

The GQ signature is `k + |n|` bits long (~148 bytes for 1024-bit `n`, ~276 bytes for 2048-bit `n`), while the RSA signature is exactly `|n|` bits (128 / 256 bytes). GQ signing and verification cost roughly the same (both need a full `v`-exponentiation plus a `d`-exponentiation), whereas RSA verification is much cheaper than RSA signing because it uses the small public exponent. Note that the GQ signing/verification timings grow much less from 1024 to 2048 bits than RSA signing does: the GQ exponents (`v` = 65537 and the 160-bit `d`) are small and fixed, while RSA signing uses a full-size private exponent (`|n|` bits).

---

## 6. Code structure

### `GQSignature.java`

Main class with two constructors:

- **`GQSignature(int bitLength, int securityParameter)`** — for the Certification Authority (CA)
  Generates the parameters: `p`, `q` (random primes of `bitLength/2` bits), `n = p·q`, `v` (starting from `65537`, incremented until `gcd(v, φ(n)) = 1`), `s = v⁻¹ mod φ(n)`
- **`GQSignature(BigInteger n, BigInteger v, int k)`** — for regular users
  Receives only the public parameters

**Main methods:**

| Method                                                          | Description                                                                              |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `generateCertificate(String identity)`                          | Computes `I = H(identity) mod n` and the certificate `J = I^s mod n` (CA only)           |
| `sign(String message, String identity, BigInteger certificate)` | Picks random `r ∈ Z*n`, `T = r^v mod n`, `d = H(M ‖ T) mod 2^k`, `y = r·J^d mod n`       |
| `verify(String message, GQSignatureData signature)`             | Recomputes `I`, `T' = y^v · I^(-d) mod n`, `d' = H(M ‖ T') mod 2^k` and checks `d' == d` |
| `getN()`, `getV()`, `getK()`                                    | Getters for the public parameters                                                        |

The hash function `H` is **SHA-256**; the challenge is reduced to `k` bits.

**Inner class `GQSignatureData`** — immutable holder for a signature: the challenge `d`, the response `y` and the signer's `identity`.

### `GQDemo.java`

Step-by-step demonstration of the complete protocol.
Tests correctness through positive and negative scenarios (tampered message, forged identity).

### `GQBenchmark.java`

Performance measurements with **JVM warmup** (10 iterations) and **100 timed iterations**.
Compares GQ with `java.security.Signature` (RSA, `SHA256withRSA`) and `javax.crypto.Cipher` (RSA, `RSA/ECB/PKCS1Padding`).
