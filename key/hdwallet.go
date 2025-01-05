package key

import (
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func seedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}

func masterDerive(seed []byte) *extKey {
  hmac := crypto.HMACSHA512(seed, []byte("Bitcoin seed"))
  prv, code := hmac[:32], hmac[32:]
  key := keyDerive(prv)
  ekey := &extKey{prvKey: *key, code: code, depth: 0, index: 0}
  return ekey
}

func privateDerive(prve []byte, depth, index uint32) *extKey {
  parPrv, parCode := prve[:32], prve[32:]
  parKey := keyDerive(parPrv)
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append(parKey.pubc, idx...) // parent public compressed
  hmac := crypto.HMACSHA512(data, parCode)
  prv, code := hmac[:32], hmac[32:]
  prvi := new(big.Int).SetBytes(prv)
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  key := keyDerive(prvi.Bytes())
  ekey := &extKey{prvKey: *key, code: code, depth: depth, index: index}
  return ekey
}

func hardenedDerive(prve []byte, depth, index uint32) *extKey {
  parPrv, parCode := prve[:32], prve[32:]
  index += uint32(1 << 31) // hardened key index
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append([]byte{0x00}, parPrv...) // parent private prefixed
  data = append(data, idx...)
  hmac := crypto.HMACSHA512(data, parCode)
  prv, code := hmac[:32], hmac[32:]
  prvi := new(big.Int).SetBytes(prv)
  prvi.Add(prvi, new(big.Int).SetBytes(parPrv))
  prvi.Mod(prvi, ecc.P256k1().Params().N)
  key := keyDerive(prvi.Bytes())
  ekey := &extKey{prvKey: *key, code: code, depth: depth, index: index}
  return ekey
}

func publicDerive(pube []byte, depth, index uint32) *extKey {
  parPubc, parCode := pube[:33], pube[33:]
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data := append([]byte{}, parPubc...) // parent public compressed
  data = append(data, idx...)
  hmac := crypto.HMACSHA512(data, parCode)
  pb, code := hmac[:32], hmac[32:]
  parX, parY := ecc.UnmarshalCompressed(ecc.P256k1(), parPubc)
  pub := new(ecdsa.PublicKey)
  pub.Curve = ecc.P256k1()
  pub.X, pub.Y = pub.ScalarBaseMult(pb)
  pubx, puby := pub.Add(pub.X, pub.Y, parX, parY)
  ekey := newExtPubKey(pubx, puby, code, depth, index)
  return ekey
}
