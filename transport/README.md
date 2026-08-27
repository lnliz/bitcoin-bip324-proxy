# BIP324 transport

`V2Transport` supports both initiator and responder roles. A transport and its
connection are one-shot: call `V2Handshake` once, use packet or message methods
only after it succeeds, and call `Destroy` after the connection is closed.

## Initiator

```go
transport, err := NewTransport(conn, uint32(wire.MainNet), true)
if err != nil {
    return err
}
defer transport.Destroy()

if err := transport.V2Handshake(); err != nil {
    return err
}
if err := transport.SendV2Message(wire.NewMsgPing(nonce)); err != nil {
    return err
}
```

## Responder

```go
transport, err := NewTransport(conn, uint32(wire.MainNet), false)
if err != nil {
    return err
}
defer transport.Destroy()

if err := transport.V2Handshake(); err != nil {
    if errors.Is(err, ErrV1Handshake) {
        prefix := transport.ReceivedPrefix()
        // Continue v1 handling with the already-consumed 16-byte prefix.
        _ = prefix
    }
    return err
}
```

`RecvV2Message` decodes payloads into btcd `wire.Message` values. Transparent
relays should use `RecvV2P2pMessage` and `SendV2MessageBuf`; those methods retain
unknown and future application payloads without requiring local typed support.

The package serializes concurrent packet sends and receives independently. It
does not set network deadlines; callers own connection timeout policy. Any
error from a packet send or receive is fatal to that channel because cipher
state may already have advanced, so close the connection instead of retrying.
Likewise, a handshake error requires closing the connection except when a
responder receives `ErrV1Handshake` and deliberately continues as v1 using the
bytes returned by `ReceivedPrefix`.
