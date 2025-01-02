package key

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/volodymyrprokopyuk/go-wallet/crypto"
)

const dictPath = "key/dictionary.txt"

func readDictionary(path string) ([]string, error) {
  file, err := os.Open(path)
  if err != nil {
    return nil, err
  }
  defer file.Close()
  dict := make([]string, 0, 2048)
  scanner := bufio.NewScanner(file)
  for scanner.Scan() {
    dict = append(dict, scanner.Text())
  }
  return dict, nil
}

func setLeadBits(bits int) byte {
  mask, m := byte(0x0), byte(0x80)
  for range bits {
    mask |= m
    m >>= 1
  }
  return mask
}

func seedGenerage(bits int, seed []byte) (string, error) {
  if !slices.Contains([]int{128, 160, 192, 224, 256}, bits) {
    return "", fmt.Errorf("invalid bit length: %d", bits)
  }
  seedLen := bits / 8
  if seed != nil {
    if len(seed) < seedLen {
      return "", fmt.Errorf(
        "seed too short: requested %d, got %d bits", bits, len(seed) * 8,
      )
    }
    seed = seed[:seedLen]
  } else {
    seed = make([]byte, seedLen)
    _, err := rand.Read(seed)
    if err != nil {
      return "", err
    }
  }
  dict, err := readDictionary(dictPath)
  if err != nil {
    return "", err
  }
  hash := crypto.SHA256(seed)
  seed = append(seed, hash[0])
  wordLen := (bits + (bits / 32)) / 11
  wordIdx := make([]uint16, wordLen)
  for i := range len(wordIdx) {
    if i > 0 {
      seed = crypto.Shl(seed, 11)
    }
    seg := crypto.Shr(seed[:2], 5)
    idx := binary.BigEndian.Uint16(seg)
    wordIdx[i] = idx
  }
  words := make([]string, wordLen)
  for i, idx := range wordIdx {
    words[i] = dict[idx]
  }
  mnemonic := strings.Join(words, " ")
  return mnemonic, nil
}

func seedVerify(mnemonic string) error {
  words := strings.Split(mnemonic, " ")
  wordLen := len(words)
  if !slices.Contains([]int{12, 15, 18, 21, 24}, wordLen) {
    return fmt.Errorf("Invalid mnemonic length: %d", wordLen)
  }
  dict, err := readDictionary(dictPath)
  if err != nil {
    return err
  }
  mapDict := make(map[string]uint16, len(dict))
  for i, word := range dict {
    mapDict[word] = uint16(i)
  }
  wordIdx := make([]uint16, wordLen)
  for i, word := range words {
    idx, exist := mapDict[word]
    if !exist {
      return fmt.Errorf("invalid mnemonic word: %s", word)
    }
    wordIdx[i] = idx
  }
  seed := make([]byte, 0)
  for i := wordLen - 1; i >= 0; i-- {
    seg := make([]byte, 2)
    binary.BigEndian.PutUint16(seg, wordIdx[i])
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
    return fmt.Errorf("seed verify: checksum mismatch")
  }
  return nil
}

func seedDerive(mnemonic, passphrase string) []byte {
  salt := []byte("mnemonic" + passphrase)
  seed := crypto.PBKDF2SHA512([]byte(mnemonic), salt, 2048, 64)
  return seed
}
