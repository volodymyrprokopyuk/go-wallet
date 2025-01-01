package key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func keyGenerate() (*ecdsa.PrivateKey, error)  {
  return ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
}

func keyDerive(prv []byte) *ecdsa.PrivateKey {
  key := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(prv)}
  key.PublicKey.Curve = ecc.P256k1()
  key.PublicKey.X, key.PublicKey.Y = key.PublicKey.ScalarBaseMult(key.D.Bytes())
  return key
}

func keyAddress(pub []byte) []byte {
  hash := crypto.Keccak256(pub)
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
