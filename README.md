elixxir/crypto
-------------------

[![pipeline status](https://gitlab.com/elixxir/crypto/badges/master/pipeline.svg)](https://gitlab.com/elixxir/crypto/commits/master)
[![coverage report](https://gitlab.com/elixxir/crypto/badges/master/coverage.svg)](https://gitlab.com/elixxir/crypto/commits/master)


This library implements functionality for cryptographic operations in
the cMix system.

It has high requirements for test coverage because of the sensitive nature of
the things that it implements, so make sure to write tests for all the new 
code you write here and cover all possible cases to prevent as many security
problems as you can.

At some point we need to reimplement everything in this library with 
constant-time implementations.

## Running tests

First, make sure the dependencies are installed by running `glide up`. Then,
run `go test ./...`

## Project structure

`cmix` derives new keys within the cyclic group from salts and a base key. 
It also is used for managing keys and salts for communication between clients 

`cryptops` includes cryptographic operations including elgamal and key generation.

`csprng` wraps the golang crypto/rand package so that we can use different 
random number generators interchangeably when the need arises.

`cyclic` wraps our large.Int structure.  It is designed to be used in conjunction with the cyclic.Group 
object. The cyclic.Group object will provide implementations of various modular operations within the group. 
A cyclic.IntBuffer type will be created to store large batches of groups.

`diffieHellman` implements a Diffie-Hellman key exchange. Includes creation of DH keypairs,
 DH session keys, and checking the validity of DH public keys.

`e2e` contains functions used in the end-to-end encryption algorithm, including
the end-to-end key rotation.

`fastRNG` includes a cryptographically secure random number generator implementation 
which highlights performance. Based off of the Fortuna construction.

`hash` includes a general-purpose hashing algorithm, blake2b, that should be 
suitable for most of our needs. It also includes functions to calculate an HMAC.

`large` wraps the golang big.Int struct such that if we 
need to come up with constant-time implementations of big integer operations to avoid leaking information, 
it's possible to incrementally replace the golang big int implementation with our own 

`nonce` contains our implementation of a nonce, including an expiration time, generation time and TTL.

`registration` contains functions for generating data for registration, 
including a base key and a user ID.

`shuffle` has a Fisher-Yates shuffle algorithm that we use for mixing 
the slots in our Permute phases.

`signature` contains parsers and handlers for RSA keys. It also includes 
wrappers to sign and verify the signatures of messages.

`tls` contains wrapper functions for creating GRPC credentials.
 It also implements RSA key parsing.
