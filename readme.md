# X448

This is a pure Rust implementation of the Diffie hellman key exchange protocol, X448. 

## Example 


## API Discussion

The API exposes 3 objects; a public key , a shared public key and a secret key.

    - The public key is an elliptic curve point. It corresponds to a Scalar that the user owns.
    - The secret key is a Scalar. This Scalar corresponds to the user's public key and the generator specified in the RFC.
    - The shared secret key is an elliptic curve point. It is the key that is computed after a key exchange.  

In our API there is only one secret scalar key. It can be seen in x25519 that there are two types of secret scalar keys;

    - An ephemeral secret key which can only be used once in a Diffie-Hellman key exchange.
    - A static secret key which can be used multiple times in a diffie hellman key exchange.

In order to replicate this functionality in this API, there are two functions for a Diffie-Hellman key exchange `to_diffie_hellman` and `as_diffie_hellman`.
Using `to_diffie_hellman` will consume the key, achieving the same outcome as an ephemeral secret key. Using `as_diffie_hellman` will immutably borrow the secret key, so that it can be re-used for subsequent key exchanges, achieving the same outcome as a static secret key.

### WARNING

THIS IMPLEMENTATION HAS NOT BEEN REVIEWED/AUDITED. THIS SHOULD NOT BE USED IN PRODUCTION.


