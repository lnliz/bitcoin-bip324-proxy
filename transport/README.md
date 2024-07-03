# bip324_transport

## V2Transport


### V2 Client Example

See `tryV2Handshake` in [proxy.go](../proxy.go)

```
import (

    ...

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"
)


    transport, err := bip324_transport.NewTransport(remoteNonn, NetMagicMainnet)
    if err != nil {
        ...
    }

    // true -> initiating the connection    
	if err := transport.V2Handshake(true); err != nil {
        ...
    }

	if err := transport.SendV2Message(msg); err != nil {
		c.Logf("c.SendV2Message(msg) err: %s", err)
		return err
	}

    ...


```



### V2 Server Example

See `v2ConnectionHandler` in [proxy_test.go](../proxy_test.go)

```
import (

    ...

	"github.com/btcsuite/btcd/wire"

	bip324_transport "github.com/lnliz/bitcoin-bip324-proxy/transport"
)

	transport, err := bip324_transport.NewTransport(conn, NetMagicMainnet)
	if err != nil {
        ...
	}

	if err := transport.V2Handshake(false); err != nil {
        ...
	}

	versionMsg := wire.NewMsgVersion( .... )

	if err := transport.SendV2Message(versionMsg); err != nil {
        ...
	}

	msg, err := transport.RecvV2Message()
	if err != nil {
        ...
	}

```