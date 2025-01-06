package crypto

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

func SHA256Cmd() *cli.Command {
  cmd := &cli.Command{
    Name: "sha256",
    Usage:  `Produce a sha256 digest
  stdin: data bytes
  stdout: a sha256 digest in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
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

func Keccak256Cmd() *cli.Command {
  cmd := &cli.Command{
    Name: "keccak256",
    Usage: `Produce a keccak256 digest
  stdin: data bytes
  sotout: a keccak256 digest in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
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

func HMACSHA512Cmd() *cli.Command {
  cmd := &cli.Command{
    Name: "hmac-sha512",
    Usage: `Produce a hmac-sha512 digest using an authenticating key
  stdin: data bytes
  stdout: a hmac-sha512 digest in hex authenticated with the key`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      key := cmd.String("key")
      data, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      hmac := HMACSHA512(data, []byte(key))
      fmt.Printf("%x\n", hmac)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "key", Usage: "an authenticating key bytes", Required: true,
    },
  }
  return cmd
}

func PBKDF2SHA512Cmd() *cli.Command {
  cmd := &cli.Command{
    Name: "pbkdf2-sha512",
    Usage: `Derive a pbkdf2-sha512 key from a password
  stdin: a password bytes
  stdout: a pbkdf-sha512 key in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      salt := cmd.String("salt")
      iter := cmd.Int("iter")
      keyLen := cmd.Int("keylen")
      pass, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      key := PBKDF2SHA512(pass, []byte(salt), int(iter), int(keyLen))
      fmt.Printf("%x\n", key)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "salt", Usage: "a salt bytes", Required: true,
    },
    &cli.IntFlag{
      Name: "iter", Usage: "a number of SHA512 iterations", Required: true,
    },
    &cli.IntFlag{
      Name: "keylen", Usage: "a length of the derived key", Required: true,
    },
  }
  return cmd
}

func Base58CheckCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "base58chk",
    Usage: "Encode and decode base58check",
    Commands: []*cli.Command{
      base58CheckEncCmd(), //base58CheckDecCmd(),
    },
  }
  return cmd
}

func base58CheckEncCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "encode",
    Usage: `Encode base58check
  stdin: a large number in hex
  stdout: a base58check encoded string`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var num []byte
      _, err := fmt.Scanf("%x", &num)
      if err != nil {
        return err
      }
      str := Base58CheckEnc(num)
      fmt.Printf("%s\n", str)
      return nil
    },
  }
  return cmd
}

// func base58CheckDecCmd() *cli.Command {
//   cmd := &cli.Command{
//     Name: "decode",
//     Usage: `Decode base58check
//   stdin: a base58check encoded string
//   stdout: a large number in hex`,
//     Action: func(ctx context.Context, cmd *cli.Command) error {
//       var str string
//       _, err := fmt.Scanf("%s", &str)
//       if err != nil {
//         return err
//       }
//       num, err := Base58CheckDecHex(str)
//       if err != nil {
//         return err
//       }
//       fmt.Printf("%x\n", num)
//       return nil
//     },
//   }
//   return cmd
// }
