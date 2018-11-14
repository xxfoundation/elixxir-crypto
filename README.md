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

`coin` contains the coin and compound data structures, and supporting 
functionality including minting for tests. Minting functionality should be 
removed or changed to a real-world model before open-sourcing or alphanet 
release.

`csprng` wraps the golang crypto/rand package so that if we come up with a 
better random number generator, we can easily switch to it.

`cyclic` wraps the golang big/Int struct so that if we need to come up with 
constant-time implementations of big integer operations to avoid leaking 
information, it's possible to incrementally replace the golang big int 
implementation with our own. It also implements modular operations within a 
cyclic group.

`diffieHellman` implements a Diffie-Hellman key exchange. At the time of 
writing, this is dead code.

`format` includes the parts of the message format that both the server and 
the client library make use of. This includes fields for nonce and MIC for 
both the recipient and payload. This package is a candidate for inclusion in 
the new `primitives` repo.

`forward` derives new keys within the cyclic group from salts and a base key.

`hash` includes a general-purpose hashing algorithm, blake2b, that should be 
suitable for most of our needs. It also includes functions to calculate an HMAC.

`id` includes a type for user IDs. Right now, user IDs are 256 bits long. 
This is a candidate for inclusion in the new `primitives` repo.

`messaging` is currently for managing keys and salts for communication between
clients.

`shuffle` has a Fisher-Yates shuffle algorithm that we use for mixing 
the slots in our Permute phases.

`verification` contains a MIC algorithm that we currently use to prevent 
men in the middle from tampering with the message while it's in the middle of 
being sent through the network.
