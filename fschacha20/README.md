# BIP324 forward-secure ChaCha wrappers

This package implements BIP324's `FSChaCha20` encrypted-length stream and
`FSChaCha20Poly1305` packet AEAD. Both rekey after every 224 operations and use
the nonce layouts specified by BIP324.

Instances are stateful and must remain dedicated to one direction. The
transport package serializes access; direct callers must do the same.
