package crypto

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

func HashCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "hash",
    Short: "Produce a sha256, keccak256 digest",
  }
  cmd.AddCommand(sha256Cmd(), keccak256Cmd())
  return cmd
}

func sha256Cmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "sha256",
    Short: `Produce a sha256 digest
  stdin: data bytes
  stdout: a sha256 digest in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      data, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      hash := SHA256(data)
      fmt.Printf("%x\n", hash)
      return nil
    },
  }
  return cmd
}

func keccak256Cmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "keccak256",
    Short: `Produce a keccak256 digest
  stdin: data bytes
  sotout: a keccak256 digest in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      data, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      hash := Keccak256(data)
      fmt.Printf("%x\n", hash)
      return nil
    },
  }
  return cmd
}

func MACCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "mac",
    Short: "Produce a hmac-sha512 authenticated digest",
  }
  cmd.AddCommand(hmacSHA512Cmd())
  return cmd
}

func hmacSHA512Cmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "hmac-sha512",
    Short: `Produce a hmac-sha512 digest using an authenticating key
  stdin: data bytes
  stdout: a hmac-sha512 digest in hex authenticated with the key`,
    RunE: func(cmd *cobra.Command, args []string) error {
      key, _ := cmd.Flags().GetString("key")
      data, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      mac := HMACSHA512(data, []byte(key))
      fmt.Printf("%x\n", mac)
      return nil
    },
  }
  cmd.Flags().String("key", "", "an authenticating key bytes")
  _ = cmd.MarkFlagRequired("key")
  return cmd
}

func KDFCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "kdf",
    Short: "Derive a pbkdf2-sha512 key",
  }
  cmd.AddCommand(pbkdf2SHA512Cmd())
  return cmd
}

func pbkdf2SHA512Cmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "pbkdf2-sha512",
    Short: `Derive a pbkdf2-sha512 key
  stdin: a password bytes
  stdout: a pbkdf-sha512 key in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      salt, _ := cmd.Flags().GetString("salt")
      iter, _ := cmd.Flags().GetInt("iter")
      keyLen, _ := cmd.Flags().GetInt("keylen")
      pass, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      key := PBKDF2SHA512(pass, []byte(salt), iter, keyLen)
      fmt.Printf("%x\n", key)
      return nil
    },
  }
  cmd.Flags().String("salt", "", "a salt bytes")
  _ = cmd.MarkFlagRequired("salt")
  cmd.Flags().Int("iter", 0, "a number of SHA512 iterations")
  _ = cmd.MarkFlagRequired("iter")
  cmd.Flags().Int("keylen", 0, "a length of the derived key")
  _ = cmd.MarkFlagRequired("keylen")
  return cmd
}

func Base58CheckCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "base58check",
    Short: "Encode and decode base58check",
  }
  cmd.AddCommand(base58CheckEncCmd(), base58CheckDecCmd())
  return cmd
}

func base58CheckEncCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "encode",
    Short: `Encode base58check
  stdin: a large number in hex
  stdout: a base58check encoded string`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var num []byte
      _, err := fmt.Scanf("%x", &num)
      if err != nil {
        return err
      }
      str := Base58CheckEncHex(num)
      fmt.Printf("%s\n", str)
      return nil
    },
  }
  return cmd
}

func base58CheckDecCmd() *cobra.Command {
  cmd := &cobra.Command{
    Use: "decode",
    Short: `Decode base58check
  stdin: a base58check encoded string
  stdout: a large number in hex`,
    RunE: func(cmd *cobra.Command, args []string) error {
      var str string
      _, err := fmt.Scanf("%s", &str)
      if err != nil {
        return err
      }
      num, err := Base58CheckDecHex(str)
      if err != nil {
        return err
      }
      fmt.Printf("%x\n", num)
      return nil
    },
  }
  return cmd
}
