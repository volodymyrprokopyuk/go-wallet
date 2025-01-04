package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

type ecKey struct {
  prv []byte // A random large number d
  pub []byte // The uncompressed public key (0x04, x, y)
  pubc []byte // The compressed public key (0x02 even y | 0x03 odd y, x)
  code []byte // The HD chain code
}

func newECKey(key *ecdsa.PrivateKey, code []byte) *ecKey {
  prv := key.D.Bytes()
  pub := append(key.X.Bytes(), key.Y.Bytes()...)
  pub = append([]byte{0x04}, pub...)
  pubc := key.X.Bytes()
  if new(big.Int).Mod(key.Y, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
    pubc = append([]byte{0x02}, pubc...)
  } else {
    pubc = append([]byte{0x03}, pubc...)
  }
  return &ecKey{prv: prv, pub: pub, pubc: pubc, code: code}
}

func (k *ecKey) yamlEncode() string {
  if len(k.code) > 0 {
    return fmt.Sprintf(
      "{prv: %064x, pub: %064x, pubc: %064x, code: %064x}",
      k.prv, k.pub, k.pubc, k.code,
    )
  }
  return fmt.Sprintf(
    "{prv: %064x, pub: %064x, pubc: %064x}", k.prv, k.pub, k.pubc,
  )
}

func keyGenerate() (*ecKey, error)  {
  key, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
  if err != nil {
    return nil, err
  }
  eckey := newECKey(key, nil)
  return eckey, nil
}

func keyDerive(prv []byte) *ecKey {
  key := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  key.PublicKey.Curve = ecc.P256k1()
  key.PublicKey.X, key.PublicKey.Y = key.PublicKey.ScalarBaseMult(key.D.Bytes())
  return newECKey(key, nil)
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
