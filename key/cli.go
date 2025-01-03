package key

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

func formatKey(key *ecdsa.PrivateKey) string {
  return fmt.Sprintf("{prv: %064x, pub: %064x%064x}", key.D, key.X, key.Y)
}

func KeyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "key",
    Usage: "Generate a secp256k1 key pair, sign a message, verify a signature",
    Commands: []*cli.Command{
      keyGenerateCmd(), keyDeriveCmd(), keyAddressCmd(),
    },
  }
  return cmd
}

func keyGenerateCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "generate",
    Usage: `Generate a secp256k1 key pair
  stdout: a key pair in hex in yaml {prv, pub}`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      key, err := keyGenerate()
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", formatKey(key))
      return nil
    },
  }
  return cmd
}

func keyDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a secp256k1 public key from an external private key
  stdin: an external private key in hex
  stdout: a key pair in hex in yaml {prv, pub}`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var prv []byte
      _, err := fmt.Scanf("%x", &prv)
      if err != nil {
        return err
      }
      key := keyDerive(prv)
      fmt.Printf("%s\n", formatKey(key))
      return nil
    },
  }
  return cmd
}

func keyAddressCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "address",
    Usage: `Derive an Ethereum address from a public key
  stdin: a public key in hex
  stdout: an Ethereum address in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var pub []byte
      _, err := fmt.Scanf("%x", &pub)
      if err != nil {
        return err
      }
      addr := keyAddress(pub)
      fmt.Printf("%x\n", addr)
      return nil
    },
  }
  return cmd
}

// func signCmd() *cobra.Command {
//   cmd := &cobra.Command{
//     Use: "sign",
//     Short: `Sign a message with a private key
//   stdin: a hash of the message
//   stdout: the signature of the message`,
//     RunE: func(cmd *cobra.Command, args []string) error {
//       key, _ := cmd.Flags().GetString("key")
//       var hash string
//       _, err := fmt.Fscanf(os.Stdin, "%s", &hash)
//       if err != nil {
//         return err
//       }
//       sig, err := sign(key, []byte(hash))
//       if err != nil {
//         return err
//       }
//       fmt.Println(base64.StdEncoding.EncodeToString(sig))
//       return nil
//     },
//   }
//   cmd.Flags().String("key", "", "private key")
//   _ = cmd.MarkFlagRequired("key")
//   return cmd
// }

// func verifyCmd() *cobra.Command {
//   cmd := &cobra.Command{
//     Use: "verify",
//     Short: `Verify a signature given a message and a public key
//   stdin: a hash of the message
//   stdout: true if the signature is valid, false otherwise`,
//     RunE: func(cmd *cobra.Command, args []string) error {
//       var hash string
//       _, err := fmt.Fscanf(os.Stdin, "%s", &hash)
//       if err != nil {
//         return err
//       }
//       ssig, _ := cmd.Flags().GetString("sig")
//       sig, err := base64.StdEncoding.DecodeString(ssig)
//       if err != nil {
//         return err
//       }
//       pub, _ := cmd.Flags().GetString("pub")
//       valid, err := verify([]byte(hash), sig, pub)
//       if err != nil {
//         return err
//       }
//       fmt.Println(valid)
//       return nil
//     },
//   }
//   cmd.Flags().String("sig", "", "message signature")
//   _ = cmd.MarkFlagRequired("pub")
//   cmd.Flags().String("pub", "", "public key")
//   _ = cmd.MarkFlagRequired("pub")
//   return cmd
// }

func AddressCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "address",
    Usage: "Encode and verify an Ethereum address (ERC-55)",
    Commands: []*cli.Command{
      addressEncodeCmd(), addressVerifyCmd(),
    },
  }
  return cmd
}

func addressEncodeCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "encode",
    Usage: `Encode an Ethereum address (ERC-55)
  stdin: an Ethereum address in hex
  stdout: an encoded case-sensitive Ethereum address string`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var addr []byte
      _, err := fmt.Scanf("%x", &addr)
      if err != nil {
        return err
      }
      encAddr := addressEncode(addr)
      fmt.Printf("%s\n", encAddr)
      return nil
    },
  }
  return cmd
}

func addressVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify an encoded case-sensitive Ethereum address (ERC-55)
  stdin: an encoded case-sensitive Ethereum address string
  stdout: true if the address is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var addr string
      _, err := fmt.Scanf("%s", &addr)
      if err != nil {
        return err
      }
      valid := true
      err = addressVerify(addr)
      if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        valid = false
      }
      fmt.Printf("%t\n", valid)
      return nil
    },
  }
  return cmd
}

func MnemonicCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "mnemonic",
    Usage: "Generate, derive, and verify a mnemonic",
    Commands: []*cli.Command{
      mnemonicGenerateCmd(), mnemonicDeriveCmd(), mnemonicVerifyCmd(),
    },
  }
  return cmd
}

func mnemonicGenerateCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "generate",
    Usage: `Generate a mnemonic that encodes a randomly generated seed (BIP-39)
  stdout: a mnemonic string that encodes the randomly generated seed`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      mnem, err := mnemonicGenerate(int(bits))
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a seed length in bits", Required: true,
    },
  }
  return cmd
}

func mnemonicDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a mnemonic that encodes an external seed (BIP-39)
  stdout: a mnemonic string that encodes the external seed`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      var seed []byte
      _, err := fmt.Scanf("%x", &seed)
      if err != nil {
        return err
      }
      mnem, err := mnemonicDerive(int(bits), seed)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a seed length in bits", Required: true,
    },
  }
  return cmd
}

func mnemonicVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify a mnemonic string against the embedded checksum
  stdin: a mnemonic string
  stdout: true if the mnemonic is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      valid := true
      err = mnemonicVerify(string(mnem))
      if err != nil {
        fmt.Fprintf(os.Stderr, "%s\n", err)
        valid = false
      }
      fmt.Printf("%t\n", valid)
      return nil
    },
  }
  return cmd
}

func SeedCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "seed",
    Usage: "Derive a seed from a mnemonic and an optional passphrase",
    Commands: []*cli.Command{
      seedDeriveCmd(),
    },
  }
  return cmd
}

func seedDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a seed from a mnemonic string and an optional passphrase
  stdin: a mnemonic string
  stdout: a seed in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      pass := cmd.String("passphrase")
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      seed := seedDerive(string(mnem), pass)
      fmt.Printf("%x\n", seed)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "passphrase", Usage: "a passphrase string",
    },
  }
  return cmd
}
