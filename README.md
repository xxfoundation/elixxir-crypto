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

`blockchain` contains the implementation of our simple blockchain.

`cmix` derives new keys within the cyclic group from salts and a base key. 
It also is used for managing keys and salts for communication between clients 

`coin` contains the coin and compound data structures, and supporting 
functionality including minting for tests. 

`csprng` wraps the golang crypto/rand package so that if we come up with a 
better random number generator, we can easily switch to it.

`cyclic` wraps the golang big/Int struct so that if we need to come up with 
constant-time implementations of big integer operations to avoid leaking 
information, it's possible to incrementally replace the golang big int 
implementation with our own. It also implements modular operations within a 
cyclic group. //TODO split this with `large`

`diffieHellman` implements a Diffie-Hellman key exchange.

`e2e` contains functions used in the end-to-end encryption algorithm, including
the end-to-end key rotation.

`hash` includes a general-purpose hashing algorithm, blake2b, that should be 
suitable for most of our needs. It also includes functions to calculate an HMAC.

`shuffle` has a Fisher-Yates shuffle algorithm that we use for mixing 
the slots in our Permute phases.
