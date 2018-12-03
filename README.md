# PQGo

**WARNING: Experimental code, don't use in production or for anything that matters.**

PQGo is a cgo wrapper around post-quantum cryptography primitives, based on the API of the NIST competition.

Currently PQGo includes the following primitives

* [Dilithium](https://pq-crystals.org/dilithium/index.shtml) (signature)
    * Version III (NIST level 2)
    * Public key: 1472 bytes
    * Secret key: 3504 bytes
    * Signature: 2701 bytes

* [Kyber](https://pq-crystals.org/kyber/index.shtml) (KEM)
    * Version: Kyber768 (161/178 pq/classical security)
    * Public key: 1088 bytes
    * Secret key: 2400 bytes
    * Ciphertext: 1152 bytes
    * Shared secret: 32 bytes

* [Round5](https://round5.org/) (KEM)
    * Version: 3KEMb (182/192 pq/classical security)
    * Public key: 780 bytes
    * Secret key: 24 bytes
    * Ciphertext: 830
    * Shared secret: 24 bytes

**Disclaimer**: The choice of these primitives should not be interpreted as an endorsement or recommendation. We are not liable for any damage etc. etc. We made some tweaks to the original C code, so if something is wrong there it may be our fault, not that of the original implementers.


## Usage

Obtain the package and test it as follows:

```
go get github.com/Teserakt-io/pqgo
cd pqgo
go test
```

Note that PQGo uses Go's recently introduced [modules](https://github.com/golang/go/wiki/Modules) (see [go.mod](go.mod))

Benchmarks can be run with [`justbench.sh`](justbench.sh). 
Note however that the underlying C code is the *reference* implementation, which may be considerably slower than optimized implementations.

Calling the algorithm from another package requires to import the package, instantiate a primitive, and call its methods. For example, to generate a Dilithium key pair:

```
import "github.com/Teserakt-io/pqgo"

(...)

d := pqgo.Dilithium{}
pk, sk, err := d.KeyGenRandom()

```

Usage is generally straightforward, based on the examples in [pqgo_test.go](pqgo_test.go).
PQGo uses the following interfaces, for KEM and signature primitives:
```
type KEM interface {
	KeyGen(ent []byte) ([]byte, []byte, error)
	KeyGenRandom() ([]byte, []byte, error)
	Encap(ent, pk []byte) ([]byte, []byte, error)
	EncapRandom(pk []byte) ([]byte, []byte, error)
	Decap(ct, sk []byte) ([]byte, error)
}

type Signature interface {
	KeyGen(ent []byte) ([]byte, []byte, error)
	KeyGenRandom() ([]byte, []byte, error)
	Sign(m, sk []byte) ([]byte, error)
	Open(sm, pk []byte) ([]byte, error)
}
```

## Adding other primitives

Adding new primitives requires to extend the NIST API with deterministic version of the key generation and encapsulation algorithms (see the `*_cgo()` C functions that we added to the original code).
Other tweaks may be needed to adapt the code to cgo.

Unit tests use the "golden" trick (as used in the [standard library](https://golang.org/src/cmd/gofmt/gofmt_test.go)) to verify test values.
If you add a new primitive, make sure to add corresponding unit tests as well as golden files matching the test vectors of the C implementation.

## IP

The copyright of the C implementations belongs to their respective authors:

* [Dilithium](https://github.com/pq-crystals/dilithium/blob/master/AUTHORS.md) ("public domain" licensing)
* [Kyber](https://github.com/pq-crystals/kyber/blob/master/AUTHORS) ("public domain" licensing)
* [Round5](https://github.com/mjosaarinen/r5nd_tiny/blob/master/LICENSE) (restrictive license)

The Go code is copyright (c) Teserakt AG, 2018, and hereby released under GPLv2.
