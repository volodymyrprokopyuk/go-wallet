package hdwallet

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

var rseqLens = []int{128, 160, 192, 224, 256} // In bits

var mnemLens = func() []int { // In words
  lens := make([]int, len(rseqLens))
  for i, bits := range rseqLens {
    lens[i] = (bits + (bits / 32)) / 11
  }
  return lens
}()

//go:embed mnemonic.txt
var nmenDict string

var idxWord = func() []string {
  words := make([]string, 0, 2048)
  scan := bufio.NewScanner(strings.NewReader(nmenDict))
  for scan.Scan() {
    words = append(words, scan.Text())
  }
  return words
}()

var wordIdx = func() map[string]uint16 {
  indices := make(map[string]uint16, len(idxWord))
  for i, word := range idxWord {
    indices[word] = uint16(i)
  }
  return indices
}()

func MnemonicGenerate(bits int) (string, error) {
  errh := "mnemonic generate"
  if !slices.Contains(rseqLens, bits) {
    return "", fmt.Errorf("%s: invalid bit length: %d", errh, bits)
  }
  rseq := make([]byte, bits / 8)
  _, err := rand.Read(rseq)
  if err != nil {
    return "", err
  }
  return MnemonicDerive(bits, rseq)
}

func MnemonicDerive(bits int, rseq []byte) (string, error) {
  errh := "mnemonic derive"
  if !slices.Contains(rseqLens, bits) {
    return "", fmt.Errorf("%s: invalid bit length: %d", errh, bits)
  }
  rseqLen := bits / 8
  if len(rseq) < rseqLen {
    err := fmt.Errorf(
      "%s: random sequence is too short: requested %d, got %d bits",
      errh, bits, len(rseq) * 8,
    )
    return "", err
  }
  rseq = rseq[:rseqLen]
  hash := crypto.SHA256(rseq)
  rseq = append(rseq, hash[0]) // At most one byte of a checksum
  mnemLen := (bits + (bits / 32)) / 11 // In words
  words := make([]string, mnemLen)
  for i := range mnemLen {
    if i > 0 {
      rseq = crypto.Shl(rseq, 11)
    }
    seg := crypto.Shr(rseq[:2], 5)
    idx := binary.BigEndian.Uint16(seg)
    words[i] = idxWord[idx]
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

func MnemonicVerify(mnem string) error {
  errh := "mnemonic verify"
  words := strings.Split(mnem, " ")
  wordLen := len(words)
  if !slices.Contains(mnemLens, wordLen) {
    return fmt.Errorf("%s: invalid mnemonic length: %d", errh, wordLen)
  }
  indices := make([]uint16, wordLen)
  for i, word := range words {
    idx, exist := wordIdx[word]
    if !exist {
      return fmt.Errorf("%s: invalid mnemonic word: %s", errh, word)
    }
    indices[i] = idx
  }
  rseq := make([]byte, 0)
  for i := wordLen - 1; i >= 0; i-- {
    seg := make([]byte, 2)
    binary.BigEndian.PutUint16(seg, indices[i])
    rseq = append(seg, rseq...)
    rseq = crypto.Shl(rseq, 5)
  }
  rseqLen := 4 * wordLen / 3 // In bytes
  chkLen := wordLen / 3 // In bits
  rseq, csum := rseq[:rseqLen], rseq[rseqLen]
  hash := crypto.SHA256(rseq)[0]
  mask := setLeadBits(chkLen)
  csum &= mask
  hash &= mask
  valid := csum == hash
  if !valid {
    return fmt.Errorf("%s: invalid checksum", errh)
  }
  return nil
}
