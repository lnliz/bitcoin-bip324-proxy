# bitcoin-bip324-proxy

allow bip324 v2 connections for bitcoin clients that don't support bip324 yet

More [BIP-324 information](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)

## architecture

```
Clients (local) <--> bitcoin-bip324-proxy <--> External p2p peers (remote)
```

## packages

- crypto
  - ellswift pub key and encrypt/decrypt primitives
- fschacha20
  - FSChaCha20 and FSChaCha20Poly1305 for stream encryption
- transport
  - v2Handshake to set up v2 bip324 server or client connection


## todo

- still lots to do :-)
- replace lots of the ugly code in crypto package
- more metrics
- more tests
- docker image
- ...


The exporter is heavily based on [the python version of the proxy by theStack](https://github.com/theStack/bip324-proxy).
