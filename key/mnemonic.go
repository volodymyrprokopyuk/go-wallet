package key

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/volodymyrprokopyuk/go-wallet/crypto"

	_ "embed"
)

var seedLens = []int{128, 160, 192, 224, 256} // in bits

var mnemLens = func() []int { // in bytes
  lens := make([]int, len(seedLens))
  for i, bits := range seedLens {
    lens[i] = (bits + (bits / 32)) / 11
  }
  return lens
}()

//go:embed mnemonic-dict.txt
var strDict string

var slcDict = func() []string {
  dict := make([]string, 0, 2048)
  scan := bufio.NewScanner(strings.NewReader(strDict))
  for scan.Scan() {
    dict = append(dict, scan.Text())
  }
  return dict
}()

var mapDict = func() map[string]uint16 {
  dict := make(map[string]uint16, len(slcDict))
  for i, word := range slcDict {
    dict[word] = uint16(i)
  }
  return dict
}()

func mnemonicGenerate(bits int) (string, error) {
  errh := "mnemonic generate"
  if !slices.Contains(seedLens, bits) {
    return "", fmt.Errorf("%s: invalid bit length: %d", errh, bits)
  }
  seed := make([]byte, bits / 8)
  _, err := rand.Read(seed)
  if err != nil {
    return "", err
  }
  return mnemonicDerive(bits, seed)
}

func mnemonicDerive(bits int, seed []byte) (string, error) {
  errh := "mnemonic derive"
  if !slices.Contains(seedLens, bits) {
    return "", fmt.Errorf("%s: invalid bit length: %d", errh, bits)
  }
  seedLen := bits / 8
  if len(seed) < seedLen {
    err := fmt.Errorf(
      "%s: seed too short: requested %d, got %d bits",
      errh, bits, len(seed) * 8,
    )
    return "", err
  }
  seed = seed[:seedLen]
  hash := crypto.SHA256(seed)
  seed = append(seed, hash[0])
  widx := make([]uint16, (bits + (bits / 32)) / 11)
  for i := range len(widx) {
    if i > 0 {
      seed = crypto.Shl(seed, 11)
    }
    seg := crypto.Shr(seed[:2], 5)
    idx := binary.BigEndian.Uint16(seg)
    widx[i] = idx
  }
  words := make([]string, len(widx))
  for i, idx := range widx {
    words[i] = slcDict[idx]
  }
  mnem := strings.Join(words, " ")
  return mnem, nil
}

func setLeadBits(bits int) byte {
  mask, m := byte(0x0), byte(0x80)
  for range bits {
    mask |= m
    m >>= 1
  }
  return mask
}

func mnemonicVerify(mnem string) error {
  errh := "mnemonic verify"
  words := strings.Split(mnem, " ")
  wordLen := len(words)
  if !slices.Contains(mnemLens, wordLen) {
    return fmt.Errorf("%s: invalid mnemonic length: %d", errh, wordLen)
  }
  widx := make([]uint16, wordLen)
  for i, word := range words {
    idx, exist := mapDict[word]
    if !exist {
      return fmt.Errorf("%s: invalid mnemonic word: %s", errh, word)
    }
    widx[i] = idx
  }
  seed := make([]byte, 0)
  for i := wordLen - 1; i >= 0; i-- {
    seg := make([]byte, 2)
    binary.BigEndian.PutUint16(seg, widx[i])
    seed = append(seg, seed...)
    seed = crypto.Shl(seed, 5)
  }
  seedLen := 4 * wordLen / 3 // in bytes
  checkLen := wordLen / 3 // in bits
  seed, checksum := seed[:seedLen], seed[seedLen]
  hash := crypto.SHA256(seed)[0]
  mask := setLeadBits(checkLen)
  checksum &= mask
  hash &= mask
  valid := checksum == hash
  if !valid {
    return fmt.Errorf("%s: invalid checksum", errh)
  }
  return nil
}

func seedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}
