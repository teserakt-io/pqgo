package pqgo

/*
#include "c/fips202/fips202.c"
#include "c/fips202/keccakf1600.c"

#include "c/randombytes/rng.c"
#include "c/randombytes/xof_hash.c"

#include "c/round5/kem_cpa.c"
#include "c/round5/encrypt.c"
#include "c/round5/ringmul.c"
#include "c/round5/ringmul_cm.c"
#include "c/round5/xecc.c"

#include "c/kyber/params.h"
#include "c/kyber/kyber_poly.c"
#include "c/kyber/kyber_polyvec.c"
#include "c/kyber/kyber_reduce.c"
#include "c/kyber/kyber_ntt.c"
#include "c/kyber/cbd.c"
#include "c/kyber/indcpa.c"
#include "c/kyber/kem.c"
#include "c/kyber/kex.c"
#include "c/kyber/precomp.c"
#include "c/kyber/verify.c"

#include "c/dilithium/params.h"
#include "c/dilithium/poly.c"
#include "c/dilithium/ntt.c"
#include "c/dilithium/packing.c"
#include "c/dilithium/sign.c"
#include "c/dilithium/polyvec.c"
#include "c/dilithium/reduce.c"
#include "c/dilithium/rounding.c"
*/
import "C"
import (
	"crypto/rand"
	"errors"
	"unsafe"
)

const (
	// DilithiumEntropyLen is the byte length of keypair entropy
	DilithiumEntropyLen = 32
	// KyberEntropyLen is the byte length of keypair entropy
	KyberEntropyLen = 48
	// Round5EntropyLen is the byte length of keypair entropy
	Round5EntropyLen = 48
)

var (
	// ErrKeypair ..
	ErrKeypair = errors.New("keypair returned non-zero")
	// ErrSign ..
	ErrSign = errors.New("sign returned non-zero")
	// ErrOpen ..
	ErrOpen = errors.New("open returned non-zero")
	// ErrEncrypt ..
	ErrEncrypt = errors.New("encrypt returned non-zero")
	// ErrDecrypt ..
	ErrDecrypt = errors.New("decrypt returned non-zero")
)

// KEM ...
type KEM interface {
	KeyGen(ent []byte) ([]byte, []byte, error)
	KeyGenRandom() ([]byte, []byte, error)
	Encap(ent, pk []byte) ([]byte, []byte, error)
	EncapRandom(pk []byte) ([]byte, []byte, error)
	Decap(ct, sk []byte) ([]byte, error)
}

// Signature ...
type Signature interface {
	KeyGen(ent []byte) ([]byte, []byte, error)
	KeyGenRandom() ([]byte, []byte, error)
	Sign(m, sk []byte) ([]byte, error)
	Open(sm, pk []byte) ([]byte, error)
}

// Dilithium ...
type Dilithium struct{}

// Kyber ...
type Kyber struct{}

// Round5 ...
type Round5 struct{}

// KeyGenRandom ...
func (d Dilithium) KeyGenRandom() (pk, sk []byte, err error) {
	ent := make([]byte, DilithiumEntropyLen)
	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}

	return d.KeyGen(ent)
}

// KeyGen ...
func (Dilithium) KeyGen(ent []byte) (pk, sk []byte, err error) {
	if len(ent) != DilithiumEntropyLen {
		return nil, nil, errors.New("invalid entropy size")
	}
	pk = make([]byte, C.DILITHIUM_PUBLICKEYBYTES)
	sk = make([]byte, C.DILITHIUM_SECRETKEYBYTES)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	ret := C.dilithium_sign_keypair_cgo(pkp, skp, entp)

	if ret != 0 {
		return nil, nil, ErrKeypair
	}

	pk = []byte(C.GoStringN(pkp, C.DILITHIUM_PUBLICKEYBYTES))
	sk = []byte(C.GoStringN(skp, C.DILITHIUM_SECRETKEYBYTES))

	return pk, sk, nil
}

// Sign ...
func (Dilithium) Sign(m, sk []byte) (sm []byte, err error) {

	if len(sk) != C.DILITHIUM_SECRETKEYBYTES {
		return nil, errors.New("invalid secret key size")
	}

	mlen := C.ulonglong(len(m))
	sm = make([]byte, mlen+C.DILITHIUM_BYTES)

	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	smp := (*C.char)(unsafe.Pointer(&sm[0]))
	mp := (*C.char)(unsafe.Pointer(&m[0]))

	ret := C.dilithium_sign_cgo(smp, mp, mlen, skp)

	if ret != 0 {
		return nil, ErrSign
	}

	sm = []byte(C.GoStringN(smp, C.int(len(m))+C.DILITHIUM_BYTES))

	return sm, nil
}

// Open ...
func (Dilithium) Open(sm, pk []byte) (m []byte, err error) {

	if len(pk) != C.DILITHIUM_PUBLICKEYBYTES {
		return nil, errors.New("invalid public key size")
	}

	smlen := C.ulonglong(len(sm))
	mlen := smlen - C.DILITHIUM_BYTES

	// C function may actually write as much as len(sm) at m!
	m = make([]byte, smlen)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	smp := (*C.char)(unsafe.Pointer(&sm[0]))
	mp := (*C.char)(unsafe.Pointer(&m[0]))

	ret := C.dilithium_sign_open_cgo(mp, smp, smlen, pkp)

	if ret != 0 {
		return nil, ErrOpen
	}

	m = []byte(C.GoStringN(mp, C.int(mlen)))

	return m, nil
}

// KyberKeyGenRandom ...
func (k Kyber) KeyGenRandom() (pk, sk []byte, err error) {
	ent := make([]byte, KyberEntropyLen)
	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}

	return k.KeyGen(ent)
}

// KeyGen ...
func (Kyber) KeyGen(ent []byte) (pk, sk []byte, err error) {
	if len(ent) != KyberEntropyLen {
		return nil, nil, errors.New("invalid entropy size")
	}
	pk = make([]byte, C.KYBER_PUBLICKEYBYTES)
	sk = make([]byte, C.KYBER_SECRETKEYBYTES)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	ret := C.kyber_kem_keypair_cgo(pkp, skp, entp)

	if ret != 0 {
		return nil, nil, ErrKeypair
	}

	pk = []byte(C.GoStringN(pkp, C.KYBER_PUBLICKEYBYTES))
	sk = []byte(C.GoStringN(skp, C.KYBER_SECRETKEYBYTES))

	return pk, sk, nil
}

// Encap ...
func (Kyber) Encap(ent []byte, pk []byte) (ct, ss []byte, err error) {

	if len(pk) != C.KYBER_PUBLICKEYBYTES {
		return nil, nil, errors.New("invalid public key size")
	}
	ct = make([]byte, C.KYBER_CIPHERTEXTBYTES)
	ss = make([]byte, C.KYBER_SYMBYTES)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	ctp := (*C.char)(unsafe.Pointer(&ct[0]))
	ssp := (*C.char)(unsafe.Pointer(&ss[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	C.kyber_kem_enc_cgo(ctp, ssp, pkp, entp)

	ct = []byte(C.GoStringN(ctp, C.KYBER_CIPHERTEXTBYTES))
	ss = []byte(C.GoStringN(ssp, C.KYBER_SYMBYTES))

	return ct, ss, nil
}

// EncapRandom ...
func (k Kyber) EncapRandom(pk []byte) (ct, ss []byte, err error) {
	ent := make([]byte, KyberEntropyLen)

	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}
	return k.Encap(ent, pk)
}

// Decap ...
func (Kyber) Decap(ct, sk []byte) (ss []byte, err error) {

	if len(sk) != C.KYBER_SECRETKEYBYTES {
		return nil, errors.New("invalid secret key size")
	}
	if len(ct) != C.KYBER_CIPHERTEXTBYTES {
		return nil, errors.New("invalid ciphertext size")
	}
	ss = make([]byte, C.KYBER_SYMBYTES)

	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	ctp := (*C.char)(unsafe.Pointer(&ct[0]))
	ssp := (*C.char)(unsafe.Pointer(&ss[0]))

	C.kyber_kem_dec_cgo(ssp, ctp, skp)

	ss = []byte(C.GoStringN(ssp, C.KYBER_SYMBYTES))

	return ss, nil
}

// KeyGenRandom ...
func (r Round5) KeyGenRandom() (pk, sk []byte, err error) {
	ent := make([]byte, Round5EntropyLen)
	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}

	return r.KeyGen(ent)
}

// KeyGen ...
func (Round5) KeyGen(ent []byte) (pk, sk []byte, err error) {
	if len(ent) != Round5EntropyLen {
		return nil, nil, errors.New("invalid entropy size")
	}
	pk = make([]byte, C.ROUND5_PUBLICKEYBYTES)
	sk = make([]byte, C.ROUND5_SECRETKEYBYTES)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	ret := C.round5_kem_keypair_cgo(pkp, skp, entp)

	if ret != 0 {
		return nil, nil, ErrKeypair
	}

	pk = []byte(C.GoStringN(pkp, C.ROUND5_PUBLICKEYBYTES))
	sk = []byte(C.GoStringN(skp, C.ROUND5_SECRETKEYBYTES))

	return pk, sk, nil
}

// Encap ...
func (Round5) Encap(ent []byte, pk []byte) (ct, ss []byte, err error) {

	if len(pk) != C.ROUND5_PUBLICKEYBYTES {
		return nil, nil, errors.New("invalid public key size")
	}
	ct = make([]byte, C.ROUND5_CIPHERTEXTBYTES)
	ss = make([]byte, C.PARAMS_SS_SIZE)

	pkp := (*C.char)(unsafe.Pointer(&pk[0]))
	ctp := (*C.char)(unsafe.Pointer(&ct[0]))
	ssp := (*C.char)(unsafe.Pointer(&ss[0]))
	entp := (*C.char)(unsafe.Pointer(&ent[0]))

	C.round5_kem_enc_cgo(ctp, ssp, pkp, entp)

	ct = []byte(C.GoStringN(ctp, C.ROUND5_CIPHERTEXTBYTES))
	ss = []byte(C.GoStringN(ssp, C.PARAMS_SS_SIZE))

	return ct, ss, nil
}

// EncapRandom ...
func (r Round5) EncapRandom(pk []byte) (ct, ss []byte, err error) {
	ent := make([]byte, Round5EntropyLen)

	_, err = rand.Read(ent)

	if err != nil {
		panic("random read failed")
	}

	return r.Encap(ent, pk)
}

// Decap ...
func (Round5) Decap(ct, sk []byte) (ss []byte, err error) {

	if len(sk) != C.ROUND5_SECRETKEYBYTES {
		return nil, errors.New("invalid secret key size")
	}
	if len(ct) != C.ROUND5_CIPHERTEXTBYTES {
		return nil, errors.New("invalid ciphertext size")
	}
	ss = make([]byte, C.PARAMS_SS_SIZE)

	skp := (*C.char)(unsafe.Pointer(&sk[0]))
	ctp := (*C.char)(unsafe.Pointer(&ct[0]))
	ssp := (*C.char)(unsafe.Pointer(&ss[0]))

	C.round5_kem_dec_cgo(ssp, ctp, skp)

	ss = []byte(C.GoStringN(ssp, C.PARAMS_SS_SIZE))

	return ss, nil
}
