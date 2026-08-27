# BIP324 cryptography

This package implements BIP324 ElligatorSwift key exchange, tagged x-only ECDH,
HKDF key derivation, garbage terminators, session IDs, and encrypted packets.
ElligatorSwift arithmetic and ECDH are delegated to btcd's maintained
`btcec/v2/ellswift` implementation; local key generation additionally enforces
the BIP324 uniform non-zero `u` sampling requirement.

`Bip324Cipher.Init` is one-shot. `Destroy` performs best-effort clearing of
reachable key material, subject to the limitations of Go's garbage-collected
runtime and standard cryptographic APIs. A cipher is stateful and not internally
synchronized; direct callers must serialize each direction and must not race
`Init` or `Destroy` with packet operations. `transport.V2Transport` provides
that packet serialization for normal network use.

The checked-in CSV files are the official BIP324 decoding, inverse, and packet
encoding vectors. Their provenance and checksums are recorded in
[`../BIP324_AUDIT.md`](../BIP324_AUDIT.md).
