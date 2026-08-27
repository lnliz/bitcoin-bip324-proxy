# bitcoin-bip324-proxy

`bitcoin-bip324-proxy` lets a local Bitcoin P2P client that speaks v1 connect
to remote peers over the encrypted [BIP324 v2 transport](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki).
Application messages are relayed without interpreting their payloads.

```
local v1 client <-> bitcoin-bip324-proxy <-> remote v2 (or fallback v1) peer
```

## Security model

BIP324 encrypts and authenticates transport bytes, but it does not authenticate
the peer's identity. The default retry behavior can be downgraded to v1 by an
active attacker; use `--v2-only` when fallback is unacceptable.

The default listener is loopback-only. Without `--peers`, the proxy uses the
`AddrYou` value in the local client's first `version` message as its outbound
target. Do not expose that listener to untrusted clients unless this routing
behavior is intended.

See [BIP324_AUDIT.md](BIP324_AUDIT.md) for the protocol compliance review,
test evidence, fixed defects, and remaining limitations.

## Build and test

Go 1.25 or newer is required.

```sh
go build ./...
go test ./...
go test -race ./...
```

To run the live regtest interoperability check against an installed Bitcoin
Core daemon:

```sh
BIP324_BITCOIND="$(command -v bitcoind)" go test ./transport -run '^TestInteropWithBitcoinCore$'
```

## Run

The default command listens for local v1 connections on `127.0.0.1:8324` and
exports Prometheus metrics on `127.0.0.1:9333`:

```sh
./bitcoin-bip324-proxy
```

For fixed remote peers, the proxy creates consecutive local listeners starting
at port 38400:

```sh
./bitcoin-bip324-proxy \
  --peers=12.34.56.78:8333,45.67.78.98:8333
```

Useful options:

- `--v2-only`: require BIP324 and disable v1 fallback.
- `--v1-only`: use v1 upstream without attempting BIP324.
- `--network=mainnet|testnet|testnet3|testnet4|signet|regtest`: select network
  magic (`testnet` is an alias for testnet3).
- `--append-proxy-user-agent`: append `/bip324-proxy:0.1/` to the relayed
  initial version user agent while preserving optional version fields.
- `--metrics-addr=`: disable the metrics listener.
- `--metrics-incl-peer-info`: add an outbound peer label. This can create
  unbounded metric cardinality when targets are not fixed.

## Packages

- `crypto`: ElligatorSwift key exchange, BIP324 HKDF state, and packet cipher.
- `fschacha20`: the forward-secure ChaCha20 and ChaCha20-Poly1305 wrappers.
- `transport`: handshake, packet framing, v2 application framing, and raw relay
  APIs.

The proxy design was based on [theStack's Python BIP324 proxy](https://github.com/theStack/bip324-proxy).
