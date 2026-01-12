# BrownBear Cryptographic Module

**Version:** 1.0 — 2025\
**Environment:** Web-based / API-less / No WebCrypto

---

## Overview

BrownBear is a standalone, pure JavaScript cryptographic library built to operate in restricted, air-gapped, or audited environments where native cryptographic APIs (e.g., WebCrypto or Node's `crypto`) are either not trusted or unavailable. It implements fully auditable and reproducible cryptographic primitives.

BrownBear prioritizes:

- Deterministic entropy collection
- Verifiable algorithmic correctness
- Side-channel resistance in critical paths
- Strict avoidance of API or hardware dependency

---

## Justification of Design Choices

### 1. No WebCrypto API

**Rationale:**

- In highly restricted environments, all external API calls may be blocked or forbidden.
- WebCrypto implementations vary by browser, sometimes introducing subtle differences or vulnerabilities.
- For ultimate auditability, the source code must be readable, traceable, and free of black-box dependencies.

### 2. SHA-256 (FIPS 180-4)

**Why:**

- Industry-standard hash function with broad acceptance in military and commercial applications.
- Deterministic, with well-documented behavior and avalanche properties.
- Tested against known NIST vectors.

**Use Cases:**

- Key derivation
- HMAC
- Entropy folding

### 3. HMAC-SHA256 (RFC 2104)

**Why:**

- Construction proven secure under standard cryptographic assumptions.
- Used in DRBG, PBKDF2, and internal validation functions.

**Use Cases:**

- HMAC-DRBG generator
- Key strengthening
- Constant-time comparisons

### 4. PBKDF2 with 500,000 iterations (RFC 8018)

**Why 500,000 iterations?**

- Modern systems handle this workload in \~1–2s — enough to deter brute force attacks.
- Equivalent to \~100x OWASP's 2024 recommendation (which is often \~10k–50k).
- Memory-Hard KDFs like Argon2 are stronger, but they require native memory access, which is not available without WASM.

**Rationale:**

- Better resistance to GPU/ASIC cracking.
- Tuned specifically for JavaScript performance profile.

**Salt Length:** 128 bits (16 bytes) — sufficient to prevent rainbow tables.

### 5. AES-256 in GCM Mode (FIPS 197 + SP 800-38D)

**Why GCM (Galois/Counter Mode)?**

- Combines encryption and integrity (AEAD — Authenticated Encryption with Associated Data).
- Well-supported, robust against chosen ciphertext attacks.
- GCM uses counter mode internally — stream cipher properties allow safe parallel encryption.

**Why 256-bit key?**

- Maximum FIPS-compliant strength.
- Long-term durability (128-bit security margin, even against post-quantum approximations).

### 6. HMAC-DRBG (SP 800-90A)

**Why not Math.random() or external entropy?**

- Non-cryptographic sources are not acceptable for secure applications.
- DRBG is seeded by active/passive entropy: keyboard timings, mouse movement, and system time.

**Why HMAC-DRBG over CTR-DRBG or Hash-DRBG?**

- Simple and suitable for JavaScript.
- Based entirely on primitives already implemented.
- Stateless generation avoids accidental leaks or reuse.

**Security Controls:**

- Pool size limited to 1024 events.
- Re-seeds after 128 entropy events and 1s minimum interval.

### 7. constantTimeEqual()

**Why a custom constant-time comparison?**

- Native JS equality checks (`===` or `.every`) may leak timing info.
- Bitwise comparison avoids early exit paths.
- Prevents classic timing attacks against HMAC or authentication tags.

---

## Test Coverage Summary

All primitives are validated against NIST vectors or internal consistency checks.

| Component         | Test Type                                   | Status |
| ----------------- | ------------------------------------------- | ------ |
| SHA-256           | Vector comparison (NIST)                    | ✅ PASS |
| HMAC-SHA256       | Output length + avalanche                   | ✅ PASS |
| PBKDF2            | Output length, known output                 | ✅ PASS |
| AES-GCM           | Round-trip encryption, tamper detection     | ✅ PASS |
| HMAC-DRBG         | Byte distribution, length, entropy response | ✅ PASS |
| constantTimeEqual | True and false detection                    | ✅ PASS |
| zeroize           | All bytes set to 0                          | ✅ PASS |

---

## Usage Notes

### Initialization

```js
await BrownBear.setPassword("TopSecretPassword");
```

### Encryption

```js
const { data, iv, tag } = BrownBear.encrypt("classified message");
```

### Decryption

```js
const message = BrownBear.decrypt(data, iv, tag);
```

---

## Known Limitations

- No hardware acceleration (expected in JS-only environments).
- No forward secrecy (no ephemeral key exchange protocol like DH/ECDH).
- Entropy collection may be weaker in headless or non-interactive environments.

---

## Recommendations

- For ultra-secure deployments, pair BrownBear with physical entropy sources (e.g., USB TRNG).
- Use over HTTPS even if encryption is local, to prevent MITM of script delivery.
- Periodically rotate passphrases or salts.

---

## References

- [FIPS 180-4: SHA-2 Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [FIPS 197: AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [SP 800-38D: AES GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [SP 800-90A: DRBG](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
- [RFC 2104: HMAC](https://tools.ietf.org/html/rfc2104)
- [RFC 8018: PBKDF2](https://tools.ietf.org/html/rfc8018)

---

*Built with fear, for liberty and auditability. ʕ´• ᴥ•̥\`ʔ*

