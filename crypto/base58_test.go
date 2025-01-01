package crypto_test

import (
	"math/big"
	"testing"

	"github.com/volodymyrprokopyuk/solidity-dex/wallet/crypto"
)

func TestBase58EncDec(t *testing.T) {
  cases := []struct{ str string; base int; exp string }{
    {"0", 10, "1"}, {"9", 10, "A"}, {"123456789", 10, "BukQL"},
    {"0c1e24e5917779d297e14d45f14e1a1a", 16, "2Vnj8gNt6nDnPzYWJ8NNA5"},
  }
  for _, c := range cases {
    num, _ := new(big.Int).SetString(c.str, c.base)
    str := crypto.Base58Enc(num)
    if str != c.exp {
      t.Errorf("invalid base58 encode: expected %v, got %v", c.exp, str)
    }
    got, err := crypto.Base58Dec(str)
    if err != nil {
      t.Fatal(err.Error())
    }
    if got.Cmp(num) != 0 {
      t.Errorf("invalid base58 decode: expected %v, got %v", num, got)
    }
  }
}
