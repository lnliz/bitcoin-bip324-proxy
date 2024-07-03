# bitcoin-bip324-proxy

allow bip324 v2 connections for bitcoin clients that don't support bip324 yet

More [BIP-324 information](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)



### architecture

```
Clients (local) <--> bitcoin-bip324-proxy <--> External p2p peers (remote)
```


### how to build

```
go build .
```


### how to run

#### simple:
```
./bitcoin-bip324-proxy
{"level":"info","message":"metrics listen addr: 127.0.0.1:9333"}
{"level":"info","message":"Listening on 127.0.0.1:8324 as proxy server"}
```
this will start proxy and listen on localhost:8324
patch your client to always connect to the proxy at port 8324 for peer connections 
and the proxy will route to the real peer address, trying v2 protocol


#### explicit peers
```
./bitcoin-bip324-proxy --peers=12.34.56.78:8333,45.67.78.98:8333
{"level":"info","message":"metrics listen addr: 127.0.0.1:9333"}
{"level":"info","message":"Listening on 127.0.0.1:38400 as direct proxy to 12.34.56.78:8333"}
{"level":"info","message":"Listening on 127.0.0.1:38401 as direct proxy to 45.67.78.98:8333"}
{"level":"info","message":"Listening on 127.0.0.1:8324 as proxy server"}
```

this will work like simple example above and in addition listen on two more ports.
now your client can use "proxy:38400 as a peer address and all traffic will get routed to the real peer "12.34.56.78:8333".
same with port 38401, it will route all traffic to real peer "45.67.78.98:8333"

in this way no patching of client is needed but the downside is that the list of peers is static.
possible improvement idea: keep listen ports static (so you can configure peers in client) but route to dynamic list of peers that is refreshing 


### packages

- crypto
  - ellswift pub key and encrypt/decrypt primitives
- fschacha20
  - FSChaCha20 and FSChaCha20Poly1305 for stream encryption
- transport
  - v2Handshake to set up v2 bip324 server or client connection


### todo

- still lots to do :-)
- replace lots of the ugly code in crypto package
- more metrics
- more tests
- docker image
- ...


The exporter is heavily based on [the python version of the proxy by theStack](https://github.com/theStack/bip324-proxy).
