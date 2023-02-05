# FROST

![ci](https://github.com/Trust-Machines/frost/actions/workflows/ci.yml/badge.svg)

[```FROST```](https://eprint.iacr.org/2020/852.pdf) is a system for making ```Flexible Round Optimized Schnorr Threshold``` signatures.  It allows a group of ```N``` parties, each of whom controls a single key, to make a valid ```Schnorr``` signature, as long as ```T``` (the ```threshold```) of them complete the protocol honestly.  While there are many other threshold signature schemes, ```FROST``` has several features which make it particularly useful in a cryptocurrency context.

First, it is optimized for a small number of rounds in the common case where there are no byzantine actors present.  Since the protocol allows detection any bad actors in the system, it makes sense to optimize for the case where there are none.  Such byzantine actors can be sanctioned in a way that severely disincentivezes attempts to subvert the protocol.

Second, in contrast to typical ```multisig``` protocols, ```FROST``` produces a single aggregate signature which is indistinguisable from a standard ```Schnorr``` signature. Crucially, this signature can be verified the same way as any ```Schnorr``` signature.  And since the signature is aggregated, it does not take any more space on chain than any other standard signature, and linearly less than traditional ```multisig``` signatures.

## Variants
This crate provides a vanilla implementation of ```FROST``` in the ```v1``` module, where each ```Party``` controls a single key.  ```v1``` also contains code which wraps a number of parties into a single ```Signer``` object.  This allows ```FROST``` to function not only as a threshold scheme, but also a weighted threshold scheme.  Each ```Signer``` is given a set of ```key_ids```, and acts as all of the wrapped parties in the protocol.  So in ```PoS``` style systems, where different actors will have power proportional to the size of their stakes, each ```v1::Signer``` will be able to vote proportionally to the number of keys it controls.

This crate also contains a version of ```FROST``` optimized for the weighted threshold scenario in the ```v2``` module.  We call this ```WTF```, or ```Weighted Threshold FROST```.  Like vanilla ```FROST```, ```WTF``` keeps a single polynomial and nonce for each ```Party```, but allows each ```Party``` to control multiple keys.  This allows for order-of-magnitude reductions in data size and number of messages for the distributed key generation (```DKG```) and signing parts of the protocol.

## p256k1
This crate uses the Bitcoin ```secp256k1``` curve.  But since the C ```libsecp256k1``` library only provides high level interfaces for operations used by Bitcoin, it was necessary to directly expose the scalars and curve points to allow arbitrary mathematical operations outside of sign/verify.  So we provide a wrapper crate around ```libsecp256k1``` which wraps the internal interfaces to scalars and points.  We call this crate [```p256k1```](https://github.com/Trust-Machines/p256k1), to denote that it is not only the same curve as ```secp256k1```, but also exposes the curve directly.
