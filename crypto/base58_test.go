package crypto_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

func TestBase58EncDec(t *testing.T) {
  cases := []struct{ hex string; exp string }{
    {"00", "1"}, {"000001", "112"},
    {"0c1e24e5917779d297e14d45f14e1a1a", "2Vnj8gNt6nDnPzYWJ8NNA5"},
    {"00000c1e24e5917779d297e14d45f14e1a1a", "112Vnj8gNt6nDnPzYWJ8NNA5"},
    {"c4e5ab84bc7a423ab6547ef398932dbdb3b5aaef939ca20cb4",
     "2NEBcCXYiwjxADo5j7XDysvTYT4rM8aQ95d"},
  }
  for _, c := range cases {
    hex := make([]byte, len(c.hex) / 2)
    _, err := fmt.Sscanf(c.hex, "%x", &hex)
    if err != nil {
      t.Fatal(err)
    }
    str := crypto.Base58Enc(hex)
    if str != c.exp {
      t.Errorf("invalid base58 encode: expected %s, got %s", c.exp, str)
    }
    got, err := crypto.Base58Dec(str)
    if err != nil {
      t.Fatal(err)
    }
    if !slices.Equal(got, hex) {
      t.Errorf("invalid base58 decode: expected %x, got %x", hex, got)
    }
  }
  // Empty input
  hex, exp := []byte{}, ""
  str := crypto.Base58Enc(hex)
  if str != exp {
    t.Errorf("invalid base58 encode: expected %s, got `%s`", exp, str)
  }
  got, err := crypto.Base58Dec(str)
  if err != nil {
    t.Fatal(err)
  }
  if !slices.Equal(got, hex) {
    t.Errorf("invalid base58 decode: expected %x, got %x", hex, got)
  }
}

func TestBase58CheckEncDec(t *testing.T) {
  cases := []struct{ hex string; exp string }{
    {"00", "1Wh4bh"}, {"000001", "11BwW2qR"},
    {"0c1e24e5917779d297e14d45f14e1a1a", "Anuw1CQ8Vrena8iT3RUKqhidFWC"},
    {"00000c1e24e5917779d297e14d45f14e1a1a", "11Anuw1CQ8Vrena8iT3RUKqfkg37n"},
    {"c4e5ab84bc7a423ab6547ef398932dbdb3b5aaef939ca20cb4",
     "9wSFthyoR53VVT3po5C5xusrfBz5gXUh91K96sxh"},
  }
  for _, c := range cases {
    hex := make([]byte, len(c.hex) / 2)
    _, err := fmt.Sscanf(c.hex, "%x", &hex)
    if err != nil {
      t.Fatal(err)
    }
    str := crypto.Base58CheckEnc(hex)
    if str != c.exp {
      t.Errorf("invalid base58check encode: expected %s, got %s", c.exp, str)
    }
    got, err := crypto.Base58CheckDec(str)
    if err != nil {
      t.Fatal(err)
    }
    if !slices.Equal(got, hex) {
      t.Errorf("invalid base58check decode: expected %x, got %x", hex, got)
    }
  }
  // Empty input
  hex, exp := []byte{}, "3QJmnh"
  str := crypto.Base58CheckEnc(hex)
  if str != exp {
    t.Errorf("invalid base58check encode: expected %s, got `%s`", exp, str)
  }
  got, err := crypto.Base58CheckDec(str)
  if err != nil {
    t.Fatal(err)
  }
  if !slices.Equal(got, hex) {
    t.Errorf("invalid base58check decode: expected %x, got %x", hex, got)
  }
}
