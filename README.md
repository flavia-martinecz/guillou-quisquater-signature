# Guillou–Quisquater Digital Signature Scheme in Z\*<sub>n</sub>

> **Modern Cryptographic Techniques** project

Java implementation of the **Guillou–Quisquater** identity-based digital signature scheme, together with a demonstration of the protocol and a comparative benchmark against **RSA**.

![Java](https://img.shields.io/badge/Java-8%2B-orange?logo=openjdk&logoColor=white)
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

| File                                                | Role                                                                                                     |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| [`GQSignature.java`](Implementation/GQSignature.java) | Main implementation of the GQ algorithm (parameter generation, certification, signing, verification)     |
| [`GQDemo.java`](Implementation/GQDemo.java)           | Complete demonstration with two users (Alice and Bob). Includes integrity and authenticity tests         |
| [`GQBenchmark.java`](Implementation/GQBenchmark.java) | Comparative performance measurements **GQ vs RSA**. Tests 1024- and 2048-bit keys                        |

In addition, the project's IEEE paper is located in [`Docs/`](Docs/):
[`GQ_Referat_IEEE.pdf`](Docs/GQ_Referat_IEEE.pdf).

---

## 2. System requirements

- **Java Development Kit (JDK) version 8 or newer**

Check the version:

```bash
java -version
javac -version
```

If `javac` is not available, install the full JDK:

| System                | Installation                                                    |
| --------------------- | --------------------------------------------------------------- |
| Windows               | Download from [adoptium.net](https://adoptium.net/) or Oracle   |
| Linux (Ubuntu/Debian) | `sudo apt install default-jdk`                                  |
| macOS                 | `brew install openjdk`                                          |

---

## 3. Compilation

Open a terminal in the [`Implementation/`](Implementation/) directory and run:

```bash
javac *.java
```

After compilation, the following `.class` files will appear:

- `GQSignature.class`
- `GQSignature$Signature.class` _(inner class for the signature)_
- `GQDemo.class`
- `GQBenchmark.class`

> **Note:** The `.class` files are excluded from the repository via [`.gitignore`](.gitignore).

---

## 4. Running

### A) Functionality demonstration

```bash
java GQDemo
```

It will display:

- System parameter generation by the CA
- Registration of users Alice and Bob
- Alice signing a message
- Bob verifying the signature
- Test with a modified message (must be **INVALID**)
- Test with a fake identity (must be **INVALID**)
- Signing and verification of a message from Bob to Alice

### B) Benchmark — GQ vs RSA performance comparison

```bash
java GQBenchmark
```

It will display:

- Execution times for **1024-bit** keys
- Execution times for **2048-bit** keys
- Comparison between GQ, RSA Signature and RSA Encryption

---

## 5. Expected results

### A) When running `GQDemo`

```text

 GUILLOU-QUISQUATER SCHEME DEMONSTRATION

[STEP 1] SYSTEM SETUP - Certification Authority (CA)
...
[STEP 5] BOB VERIFIES ALICE'S SIGNATURE
Verification result: VALID

[STEP 6] INTEGRITY TEST - Modified Message
Verification result: INVALID
Correct! The modified message was detected.

[STEP 7] AUTHENTICITY TEST - Fake Identity
Verification result: INVALID
Correct! The fake identity was detected.
...
ALL TESTS EXECUTED SUCCESSFULLY!
```

### B) When running `GQBenchmark`

```text

 BENCHMARK GUILLOU-QUISQUATER vs RSA


--- Key size: 1024 bits ---

GUILLOU-QUISQUATER:
  System setup:           XXX ms
  Certificate generation: XXX ms
  Signing (average):      XXX ms
  Verification (average): XXX ms
  Verification valid:     YES
  Signature size:         XXX bytes

RSA SIGNATURE (SHA256withRSA):
  Key generation:         XXX ms
  Signing (average):      XXX ms
  Verification (average): XXX ms
  ...
```

---

## 6. Code structure

### `GQSignature.java`

Main class with two constructors:

- **`GQSignature(int bitLength, int k)`** — for the Certification Authority (CA)
  Generates the parameters: `p`, `q` (primes), `n = p·q`, `v = 65537`, `s = v⁻¹ mod φ(n)`
- **`GQSignature(BigInteger n, BigInteger v, int k)`** — for regular users
  Receives only the public parameters

**Main methods:**

| Method                                                        | Description                        |
| ------------------------------------------------------------- | ---------------------------------- |
| `generateCertificate(String identity)`                        | Computes `J = H(ID)^s mod n`       |
| `sign(String message, String identity, BigInteger certificate)` | Generates the GQ signature       |
| `verify(String message, Signature sig)`                       | Checks the validity of the signature |

### `GQDemo.java`

Step-by-step demonstration of the complete protocol.
Tests correctness through positive and negative scenarios.

### `GQBenchmark.java`

Performance measurements with **JVM warmup** and **100 iterations**.
Compares GQ with `java.security.Signature` (RSA) and `javax.crypto.Cipher` (RSA).
