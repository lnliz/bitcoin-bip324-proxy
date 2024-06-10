# bip324_crypto

## EllswiftExchange

Example:
```
    privkeyBytes := []byte{...}
    pubkeyOurs := []byte{...}
    pubkeyTheirs := []byte{...}

    ex, err := NewEllswiftExchangeFromKeys(secp256k1.PrivKeyFromBytes(privkeyBytes), pubkeyOurs)
    if err != nil {
        return err
    }

    sharedSecret, err := ex.ComputeSharedSecret(pubkeyTheirs, tst.isInit)
    if err != nil {
        return err
    }

    // sharedSecret is the shared secret used for encrypting the session

```




## Test Vectors

Test vector csv files from:
https://github.com/bitcoin/bips/blob/e2f7481a132e1c5863f5ffcbff009964d7c2af20/bip-0324.mediawiki#test-vectors
