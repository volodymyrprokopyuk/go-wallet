package key

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"
	"slices"

	"github.com/dustinxie/ecc"
	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

var (
  xprvVer = []byte{0x04, 0x88, 0xad, 0xe4}
  xpubVer = []byte{0x04, 0x88, 0xb2, 0x1e}
)

func ekeyEncode(
  version []byte, depth uint8, parent []byte, index uint32, code, key []byte,
) string {
  var data bytes.Buffer
  data.Write(version)
  data.Write([]byte{depth})
  switch {
  case parent == nil: // master key
    data.Write([]byte{0x00, 0x00, 0x00, 0x00})
  case len(parent) == 4: // parent hash
    data.Write(parent)
  default: // parent pubc
    hash := crypto.RIPEMD160(crypto.SHA256(parent))
    data.Write(hash[:4])
  }
  idx := make([]byte, 4)
  binary.BigEndian.PutUint32(idx, index)
  data.Write(idx)
  data.Write(code)
  if len(key) == 32 { // private key
    data.Write([]byte{0x00})
  }
  data.Write(key)
  csum := crypto.SHA256(crypto.SHA256(data.Bytes()))
  data.Write(csum[:4])
  num := new(big.Int).SetBytes(data.Bytes())
  str := crypto.Base58Enc(num)
  return str
}

func ekeyDecode(str string) (*extKey, error) {
  num, err := crypto.Base58Dec(str)
  if err != nil {
    return nil, err
  }
  data := num.Bytes()
  version := data[:4]
  depth := uint8(data[4])
  parent := data[5:9]
  index := binary.BigEndian.Uint32(data[9:13])
  code := data[13:45]
  if slices.Equal(version, xprvVer) {
    prv := data[46:78]
    key := keyDerive(prv)
    ekey := &extKey{prvKey: *key, code: code, depth: depth, index: index}
    ekey.xprv = ekeyEncode(xprvVer, depth, parent, index, code, ekey.prv)
    ekey.xpub = ekeyEncode(xpubVer, depth, parent, index, code, ekey.pubc)
    return ekey, nil
  } else {
    pubc := data[45:78]
    pubx, puby := ecc.UnmarshalCompressed(ecc.P256k1(), pubc)
    ekey := newExtPubKey(pubx, puby, code, depth, index)
    ekey.xpub = ekeyEncode(xpubVer, depth, parent, index, code, ekey.pubc)
    return ekey, nil
  }
}

func seedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}

func masterDerive(seed []byte) *extKey {
  depth, index := uint8(0), uint32(0)
  hmac := crypto.HMACSHA512(seed, []byte("Bitcoin seed"))
  prv, code := hmac[:32], hmac[32:]
  key := keyDerive(prv)
  ekey := &extKey{prvKey: *key, code: code, depth: depth, index: index}
  ekey.xprv = ekeyEncode(xprvVer, depth, nil, index, code, prv)
  ekey.xpub = ekeyEncode(xpubVer, depth, nil, index, code, ekey.pubc)
  return ekey
}

func privateDerive(prve []byte, depth uint8, index uint32) *extKey {
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
  ekey.xprv = ekeyEncode(xprvVer, depth, parKey.pubc, index, code, ekey.prv)
  ekey.xpub = ekeyEncode(xpubVer, depth, parKey.pubc, index, code, ekey.pubc)
  return ekey
}

func hardenedDerive(prve []byte, depth uint8, index uint32) *extKey {
  parPrv, parCode := prve[:32], prve[32:]
  parKey := keyDerive(parPrv) // only for xprv and xpub
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
  ekey.xprv = ekeyEncode(xprvVer, depth, parKey.pubc, index, code, ekey.prv)
  ekey.xpub = ekeyEncode(xpubVer, depth, parKey.pubc, index, code, ekey.pubc)
  return ekey
}

func publicDerive(pube []byte, depth uint8, index uint32) *extKey {
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
  ekey.xpub = ekeyEncode(xpubVer, depth, parPubc, index, code, ekey.pubc)
  return ekey
}
