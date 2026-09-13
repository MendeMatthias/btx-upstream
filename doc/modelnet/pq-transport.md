# Strict PQ1 model transport

New model-subsystem security uses **strict post-quantum** cryptography.

## Required

- TLS 1.3 only
- Pure **ML-KEM-768** (never `X25519`, `X25519MLKEM768`, `SecP256r1MLKEM768`)
- **ML-DSA-44** certificates (`mldsa44`)
- Ciphersuite `TLS_AES_256_GCM_SHA384`
- No 0-RTT, no session tickets, no resumption
- Fail closed: if PQ1 cannot be configured, `btx-modeld` exits and
  monetary `btxd` continues

Model identities are ML-DSA-44 keys via libbitcoinpqc. They are **not**
wallet keys.

Artifact encryption at rest uses XChaCha20-Poly1305 (IETF, 24-byte nonce)
with domain-separated SHA-384 and HKDF-SHA384.

This host's system OpenSSL 3.5.5 exposes both `MLKEM768` and hybrid groups.
The model SSL_CTX pins `MLKEM768` only. Tests inspect negotiated group, version,
and ciphersuite and reject a hybrid peer.
