package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

type PubKey struct {
  Pub []byte // A uncompressed public key (0x04, x, y) 65 bytes
  Pubc []byte // A compressed public key (0x02 y even | 0x03 y odd, x) 33 bytes
}

func NewPubKey(pubx, puby *big.Int) *PubKey {
  pub := append(pubx.Bytes(), puby.Bytes()...)
  pub = append([]byte{0x04}, pub...)
  pubc := pubx.Bytes()
  if new(big.Int).Mod(puby, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
    pubc = append([]byte{0x02}, pubc...)
  } else {
    pubc = append([]byte{0x03}, pubc...)
  }
  return &PubKey{Pub: pub, Pubc: pubc}
}

func (k *PubKey) YAMLEncode() string {
  return fmt.Sprintf("{pub: %0128x, pubc: %065x}", k.Pub, k.Pubc)
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
    "{prv: %064x, pub: %0128x, pubc: %065x}", k.Prv, k.Pub, k.Pubc,
  )
}

type ExtKey struct {
  PrvKey
  Code []byte // A HD chain code 32 bytes
  Depth uint8 // A depth of the HD key from the master
  Index uint32 // A index of the HD key from the parent
  Xprv string // A encoded HD extended private key
  Xpub string // A encoded HD extended public key
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
      "{pub: %0128x, pubc: %065x, code: %064x, depth: %d, index: %d, xpub: %s}",
      k.Pub, k.Pubc, k.Code, k.Depth, k.Index, k.Xpub,
    )
  default: // HD private extended key
    return fmt.Sprintf(
      "{prv: %064x, pub: %0128x, pubc: %065x, code: %064x, depth: %d, index: %d, xprv: %s, xpub: %s}",
      k.Prv, k.Pub, k.Pubc, k.Code, k.Depth, k.Index, k.Xprv, k.Xpub,
    )
  }
}

func KeyGenerate() (*PrvKey, error)  {
  k, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
  if err != nil {
    return nil, err
  }
  key := NewPrvKey(k.D, k.X, k.Y)
  return key, nil
}

func KeyDerive(prv []byte) *PrvKey {
  k := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  k.PublicKey.Curve = ecc.P256k1()
  k.PublicKey.X, k.PublicKey.Y = k.PublicKey.ScalarBaseMult(k.D.Bytes())
  key := NewPrvKey(k.D, k.X, k.Y)
  return key
}

func KeyAddress(pub []byte) []byte {
  hash := crypto.Keccak256(pub[1:])
  addr := hash[12:]
  return addr
}

// func sign(key string, hash []byte) ([]byte, error) {
//   prv, err := keyDerive(key)
//   if err != nil {
//     return nil, err
//   }
//   return ecc.SignBytes(prv, hash, ecc.LowerS | ecc.RecID)
// }

// func verify(hash, sig []byte, pub string) (bool, error) {
//   p, err := ecc.RecoverPubkey("P-256k1", hash, sig)
//   if err != nil {
//     return false, err
//   }
//   rpub := fmt.Sprintf("%x%x", p.X, p.Y)
//   valid := rpub == pub
//   return valid, nil
// }
