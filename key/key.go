package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

type pubKey struct {
  pub []byte // A uncompressed public key (0x04, x, y) 65 bytes
  pubc []byte // A compressed public key (0x02 y even | 0x03 y odd, x) 33 bytes
}

func newPubKey(pubx, puby *big.Int) *pubKey {
  pub := append(pubx.Bytes(), puby.Bytes()...)
  pub = append([]byte{0x04}, pub...)
  pubc := pubx.Bytes()
  if new(big.Int).Mod(puby, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
    pubc = append([]byte{0x02}, pubc...)
  } else {
    pubc = append([]byte{0x03}, pubc...)
  }
  return &pubKey{pub: pub, pubc: pubc}
}

// func (k *pubKey) yamlEncode() string {
//   return fmt.Sprintf("{pub: %064x, pubc: %064x}", k.pub, k.pubc)
// }

type prvKey struct {
  pubKey
  prv []byte // A random large number d 32 bytes
}

func newPrvKey(prvd, pubx, puby *big.Int) *prvKey {
  prv := prvd.Bytes()
  pub := newPubKey(pubx, puby)
  return &prvKey{prv: prv, pubKey: *pub}
}

func (k *prvKey) yamlEncode() string {
  return fmt.Sprintf(
    "{prv: %064x, pub: %064x, pubc: %064x}", k.prv, k.pub, k.pubc,
  )
}

type extKey struct {
  prvKey
  code []byte // A HD chain code 32 bytes
  depth uint32 // A depth of the HD key from the master
  index uint32 // A index of the HD key from the parent
  xprv string // A encoded HD extended private key
  xpub string // A encoded HD extended public key
}

// func newExtPrvKey(
//   prvd, pubx, puby *big.Int, code []byte, depth, index uint32,
// ) *extKey {
//   prv := newPrvKey(prvd, pubx, puby)
//   return &extKey{prvKey: *prv, code: code, depth: depth, index: index}
// }

func newExtPubKey(
  pubx, puby *big.Int, code []byte, depth, index uint32,
) *extKey {
  pub := newPubKey(pubx, puby)
  prv := prvKey{pubKey: *pub}
  return &extKey{prvKey: prv, code: code, depth: depth, index: index}
}

func (k *extKey) yamlEncode() string {
  switch {
  case len(k.prv) == 0: // HD public extended key
    return fmt.Sprintf(
      "{pub: %064x, pubc: %064x, code: %064x, depth: %d, index %d, xpub: %s}",
      k.pub, k.pubc, k.code, k.depth, k.index, k.xpub,
    )
  default: // HD private extended key
    return fmt.Sprintf(
      "{prv: %064x, pub: %064x, pubc: %064x, code: %064x, depth: %d, index %d, xprv: %s, xpub: %s}",
      k.prv, k.pub, k.pubc, k.code, k.depth, k.index, k.xprv, k.xpub,
    )
  }
}

func keyGenerate() (*prvKey, error)  {
  k, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
  if err != nil {
    return nil, err
  }
  key := newPrvKey(k.D, k.X, k.Y)
  return key, nil
}

func keyDerive(prv []byte) *prvKey {
  k := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  k.PublicKey.Curve = ecc.P256k1()
  k.PublicKey.X, k.PublicKey.Y = k.PublicKey.ScalarBaseMult(k.D.Bytes())
  key := newPrvKey(k.D, k.X, k.Y)
  return key
}

func keyAddress(pub []byte) []byte {
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
