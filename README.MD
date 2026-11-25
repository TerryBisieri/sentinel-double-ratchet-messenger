# Aegis E2EE — Double Ratchet Messaging Engine & Telemetry Dashboard

A zero-dependency Node.js implementation of the **Signal Double Ratchet Protocol** built on the WebCrypto (`SubtleCrypto`) API. Designed for high-assurance communications requiring **Forward Secrecy**, **Break-in Recovery (Post-Compromise Security)**, **Out-of-Order Packet Resilience**, and **Auditable Key Escrow**.

## Key Security Architecture

* **Asymmetric & Symmetric Ratcheting:** Combines Diffie-Hellman key exchanges (`ECDH P-384`) and `HKDF-SHA256` root key updates with one-way `HMAC-SHA256` chain ratchets so every message uses an ephemeral, single-use `AES-256-GCM` key.
* **Authenticated Packet Headers:** Serialized ratchet metadata (`dh`, `pn`, `n`, ephemeral escrow keys, and random 128-bit IVs) is cryptographically bound via AES-GCM Additional Authenticated Data (AAD) to prevent replay and header-tampering attacks.
* **Out-of-Order Delivery Resilience:** Implements bounded skipped-message key caching (`MAX_SKIP`) to decrypt delayed or shuffled packets across DH ratchet boundaries while maintaining $O(1)$ steady-state key memory.
* **Public Key Infrastructure (PKI):** Enforces `ECDSA P-384` certificate signature verification prior to session initialization to mitigate Man-in-the-Middle (MitM) key substitution.
* **Lawful Key Escrow Module:** Per-message ephemeral key encapsulation allowing authorized audit decryption without compromising peer-to-peer forward secrecy against third-party eavesdroppers.

## Architecture Overview

```text
[Client A] ──(ECDH P-384 + HKDF)──> Root Key (RK) ──> Chain Key (CK) ──> AES-GCM Message Key (MK)
                                                                               │
[Wire Packet] = { Header (dh, n, pn, IVs, Escrow) [AAD] } + { AES-GCM Ciphertext }