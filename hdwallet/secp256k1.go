package hdwallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
)

type PubKey struct {
  Pub []byte // An uncompressed public key (0x04, x, y) 65 bytes
  Pubc []byte // A compressed public key (0x02 y even | 0x03 y odd, x) 33 bytes
}

func NewPubKey(pubx, puby *big.Int) *PubKey {
  var pub bytes.Buffer
  pub.Write([]byte{0x04})
  pub.Write(pubx.Bytes())
  pub.Write(puby.Bytes())
  var pubc bytes.Buffer
  if new(big.Int).Mod(puby, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
    pubc.Write([]byte{0x02})
  } else {
    pubc.Write([]byte{0x03})
  }
  pubc.Write(pubx.Bytes())
  return &PubKey{Pub: pub.Bytes(), Pubc: pubc.Bytes()}
}

func (k *PubKey) YAMLEncode() string {
  return fmt.Sprintf("{pub: %0130x, pubc: %066x}", k.Pub, k.Pubc)
}

type PrvKey struct {
  PubKey
  Prv []byte // A random large number d 32 bytes
}

func NewPrvKey(prvd, pubx, puby *big.Int) *PrvKey {
  prv := prvd.Bytes()
  pub := NewPubKey(pubx, puby)
  return &PrvKey{Prv: prv, PubKey: *pub}
}

func (k *PrvKey) YAMLEncode() string {
  return fmt.Sprintf(
    "{prv: %064x, pub: %0130x, pubc: %066x}", k.Prv, k.Pub, k.Pubc,
  )
}

type ExtKey struct {
  PrvKey
  Code []byte // A chain code 32 bytes
  Depth uint8 // A depth of an extended key from the master key
  Index uint32 // An index of an extended key from the parent key
  Xprv string // An encoded HD extended private key
  Xpub string // An encoded HD extended public key
}

func NewExtPrvKey(
  prvd, pubx, puby *big.Int, code []byte, depth uint8, index uint32,
) *ExtKey {
  prv := NewPrvKey(prvd, pubx, puby)
  return &ExtKey{PrvKey: *prv, Code: code, Depth: depth, Index: index}
}

func NewExtPubKey(
  pubx, puby *big.Int, code []byte, depth uint8, index uint32,
) *ExtKey {
  pub := NewPubKey(pubx, puby)
  prv := PrvKey{PubKey: *pub}
  return &ExtKey{PrvKey: prv, Code: code, Depth: depth, Index: index}
}

func (k *ExtKey) YAMLEncode() string {
  switch {
  case len(k.Prv) == 0: // HD public extended key
    return fmt.Sprintf(
      "{pub: %0130x, pubc: %066x, code: %064x, depth: %d, index: %d, xpub: %s}",
      k.Pub, k.Pubc, k.Code, k.Depth, k.Index, k.Xpub,
    )
  default: // HD private extended key
    return fmt.Sprintf(
      "{prv: %064x, pub: %0130x, pubc: %066x, code: %064x, depth: %d, index: %d, xprv: %s, xpub: %s}",
      k.Prv, k.Pub, k.Pubc, k.Code, k.Depth, k.Index, k.Xprv, k.Xpub,
    )
  }
}

func ECKeyGenerate() (*PrvKey, error)  {
  k, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
  if err != nil {
    return nil, err
  }
  key := NewPrvKey(k.D, k.X, k.Y)
  return key, nil
}

func ECKeyDerive(prv []byte) *PrvKey {
  k := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  k.PublicKey.Curve = ecc.P256k1()
  k.PublicKey.X, k.PublicKey.Y = k.PublicKey.ScalarBaseMult(k.D.Bytes())
  key := NewPrvKey(k.D, k.X, k.Y)
  return key
}

func ECDSASign(hash, prv []byte) ([]byte, error) {
  if len(hash) != 32 {
    return nil, fmt.Errorf("ECDSA sign: invalid hash length: %d", len(hash))
  }
  if len(prv) != 32 {
    return nil, fmt.Errorf("ECDSA sign: invalid private key length: %d", len(prv))
  }
  k := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  k.PublicKey.Curve = ecc.P256k1()
  return ecc.SignBytes(k, hash, ecc.LowerS | ecc.RecID)
}

func ECDSAVerify(hash, sig, pub []byte) error {
  var pubx, puby *big.Int
  switch {
  case len(pub) == 65 && pub[0] == 0x04: // Uncompressed public key
    pubx = new(big.Int).SetBytes(pub[1:33])
    puby = new(big.Int).SetBytes(pub[33:])
  case len(pub) == 33 && (pub[0] == 0x02 || pub[0] == 0x03): // Compressed public key
    pubx, puby = ecc.UnmarshalCompressed(ecc.P256k1(), pub)
  default:
    return fmt.Errorf("ECDSA verify: invalid public key %x", pub)
  }
  k := &ecdsa.PublicKey{Curve: ecc.P256k1(), X: pubx, Y: puby,}
  valid := ecc.VerifyBytes(k, hash, sig, ecc.LowerS | ecc.RecID)
  if !valid {
    return fmt.Errorf("ECDSA verify: invalid signature")
  }
  return nil
}

func ECDSARecover(hash, sig []byte) (*PubKey, error) {
  k, err := ecc.RecoverPubkey("P-256k1", hash, sig)
  if err != nil {
    return nil, err
  }
  pub := NewPubKey(k.X, k.Y)
  return pub, nil
}
