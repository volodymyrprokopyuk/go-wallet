package crypto

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const alpha58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var digit58 = func() map[uint8]int64 {
  m := make(map[uint8]int64)
  for i := 0; i < len(alpha58); i++ {
    m[alpha58[i]] = int64(i)
  }
  return m
}()

func strReverse(str string) string {
  var rev strings.Builder
  for i := len(str) - 1; i >= 0; i-- {
    rev.WriteByte(str[i])
  }
  return rev.String()
}

func Base58Enc(num *big.Int) string {
  zero, base58 := big.NewInt(0), big.NewInt(58)
  if num.Cmp(zero) == 0 {
    return "1"
  }
  quot, rem := new(big.Int).SetBytes(num.Bytes()), big.NewInt(0)
  var rev strings.Builder
  for quot.Cmp(zero) != 0 {
    quot.DivMod(quot, base58, rem)
    rev.WriteByte(alpha58[rem.Int64()])
  }
  str := strReverse(rev.String())
  return str
}

func Base58Dec(str string) (*big.Int, error) {
  if len(str) == 0 {
    return nil, fmt.Errorf("empty base58 encoded string")
  }
  num, base58 := big.NewInt(0), big.NewInt(58)
  for i := 0; i < len(str); i ++ {
    digit, exist := digit58[str[i]]
    if !exist {
      return nil, fmt.Errorf("invalid base58 digit: %c", str[i])
    }
    num.Mul(num, base58)
    num.Add(num, big.NewInt(digit))
  }
  return num, nil
}

func Base58CheckEnc(num *big.Int) string {
  data := num.Bytes()
  checksum := SHA256(SHA256(data))[:4]
  data = append(data, checksum...)
  num = new(big.Int).SetBytes(data)
  str := Base58Enc(num)
  return str
}

func Base58CheckDec(str string) (*big.Int, error) {
  num, err := Base58Dec(str)
  if err != nil {
    return nil, err
  }
  data := num.Bytes()
  l := len(data) - 4
  data, checksum := data[:l], data[l:]
  hash := SHA256(SHA256(data))
  if !bytes.Equal(hash[:4], checksum) {
    return nil, fmt.Errorf("invalid base58check checksum")
  }
  num = new(big.Int).SetBytes(data)
  return num, nil
}

var reLeadZero = regexp.MustCompile(`0+`)

func Base58CheckEncHex(hex []byte) string {
  num := new(big.Int).SetBytes(hex)
  str := Base58CheckEnc(num)
  leadZero := reLeadZero.FindString(fmt.Sprintf("%x", hex))
  str = strings.Repeat("1", len(leadZero) / 2) + str
  return str
}

var reLeadOne = regexp.MustCompile(`^1+`)

func Base58CheckDecHex(str string) ([]byte, error) {
  num, err := Base58CheckDec(str)
  if err != nil {
    return nil, err
  }
  hex := num.Bytes()
  leadOne := reLeadOne.FindString(str)
  hex = append(bytes.Repeat([]byte{0x0}, len(leadOne)), hex...)
  return hex, nil
}
