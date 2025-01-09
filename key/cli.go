package key

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v3"
)

func KeyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "key",
    Usage: "Generate a secp256k1 key pair, sign a transaction, verify a signature",
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
  stdout: a secp256k1 key pair in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      key, err := KeyGenerate()
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", key.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func keyDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a secp256k1 public key from an external secp256k1 private key
  stdin: an external secp256k1 private key in hex
  stdout: a secp256k1 key pair in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var prv []byte
      _, err := fmt.Scanf("%x", &prv)
      if err != nil {
        return err
      }
      key := KeyDerive(prv)
      fmt.Printf("%s\n", key.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func keyAddressCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "address",
    Usage: `Derive an Ethereum address from a secp256k1 public key
  stdin: a secp256k1 public key in hex
  stdout: an Ethereum address in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var pub []byte
      _, err := fmt.Scanf("%x", &pub)
      if err != nil {
        return err
      }
      addr := KeyAddress(pub)
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
      encAddr := AddressEncode(addr)
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
      err = AddressVerify(addr)
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
    Usage: "Generate, derive, and verify a mnemonic (BIP-39)",
    Commands: []*cli.Command{
      mnemonicGenerateCmd(), mnemonicDeriveCmd(), mnemonicVerifyCmd(),
    },
  }
  return cmd
}

func mnemonicGenerateCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "generate",
    Usage: `Generate a mnemonic that encodes a random sequence of bytes (BIP-39)
  stdout: a mnemonic string that encodes a random sequence of bytes`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      mnem, err := MnemonicGenerate(int(bits))
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a length in bits of a random sequence of bytes",
      Required: true,
    },
  }
  return cmd
}

func mnemonicDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "derive",
    Usage: `Derive a mnemonic that encodes an external random sequence of bytes (BIP-39)
  stdin: a random sequence of bytes in hex
  stdout: a mnemonic string that encodes the external random sequence of bytes`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      bits := cmd.Int("bits")
      var rseq []byte
      _, err := fmt.Scanf("%x", &rseq)
      if err != nil {
        return err
      }
      mnem, err := MnemonicDerive(int(bits), rseq)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", mnem)
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "bits", Usage: "a length in bits of a random sequence of bytes",
      Required: true,
    },
  }
  return cmd
}

func mnemonicVerifyCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "verify",
    Usage: `Verify a mnemonic string against the embedded checksum (BIP-39)
  stdin: a mnemonic string
  stdout: true if the mnemonic is valid, false otherwise`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      valid := true
      err = MnemonicVerify(string(mnem))
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

func HDCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "hd",
    Usage: "Derive master and children extended public and private keys",
    Commands: []*cli.Command{
      seedDeriveCmd(), masterDeriveCmd(), privateDeriveCmd(),
      hardenedDeriveCmd(), publicDeriveCmd(), pathDeriveCmd(), ekeyDecodeCmd(),
    },
  }
  return cmd
}

func seedDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "seed",
    Usage: `Derive a seed from a mnemonic and an optional passphrase
  stdin: a mnemonic string
  stdout: a seed in hex`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      pass := cmd.String("passphrase")
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      seed := SeedDerive(string(mnem), pass)
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

func masterDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "master",
    Usage: `Derive master extended private and public keys from a seed
  stdin: a seed in hex
  stdout: master extended private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var seed []byte
      _, err := fmt.Scanf("%x", &seed)
      if err != nil {
        return err
      }
      ekey := MasterDerive(seed)
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  return cmd
}

func privateDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "private",
    Usage: `Derive child extended private and public keys from a parent
extended private key and a key index
  stdin: a parent extended private key in hex
  stdout: child extended private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var prve []byte
      _, err := fmt.Scanf("%x", &prve)
      if err != nil {
        return err
      }
      ekey := PrivateDerive(prve, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a key depth from the master", Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "a key index from the parent", Required: true,
    },
  }
  return cmd
}

func hardenedDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "hardened",
    Usage: `Derive hardened child extended private and public keys from a parent
extended private key and a key index
  stdin: a parent extended private key in hex
  stdout: child extended private and public keys in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var prve []byte
      _, err := fmt.Scanf("%x", &prve)
      if err != nil {
        return err
      }
      ekey := HardenedDerive(prve, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a key depth from the master", Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "a key index from the parent, (2 << 31) will be added",
      Required: true,
    },
  }
  return cmd
}

func publicDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "public",
    Usage: `Derive a child extended public key from a parent
extended public key and a key index
  stdin: a parent extended public key in hex
  stdout: a child extended public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      depth, index := cmd.Int("depth"), cmd.Int("index")
      var pube []byte
      _, err := fmt.Scanf("%x", &pube)
      if err != nil {
        return err
      }
      ekey := PublicDerive(pube, uint8(depth), uint32(index))
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.IntFlag{
      Name: "depth", Usage: "a key depth from the master", Required: true,
    },
    &cli.IntFlag{
      Name: "index", Usage: "a key index from the parent", Required: true,
    },
  }
  return cmd
}

func pathDeriveCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "path",
    Usage: `Derive an extended private or public key defined by a HD path
  stdin: a mnemonic string
  stdout: an extended private or public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      pass := cmd.String("passphrase")
      path := cmd.String("path")
      var mnem []byte
      mnem, err := io.ReadAll(os.Stdin)
      if err != nil {
        return err
      }
      ekey, err := PathDerive(string(mnem), pass, path)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  cmd.Flags = []cli.Flag{
    &cli.StringFlag{
      Name: "passphrase", Usage: "a passphrase string",
    },
    &cli.StringFlag{
      Name: "path", Usage: "a HD path e.g. m/0'/1", Required: true,
    },
  }
  return cmd
}

func ekeyDecodeCmd() *cli.Command {
  cmd := &cli.Command{
    Name: "decode",
    Usage: `Decode a base58 encoded extended private or public key
  stdin: a base58 encoded extended private or public key
  stdout: an extended private or public key in hex in YAML`,
    Action: func(ctx context.Context, cmd *cli.Command) error {
      var str string
      _, err := fmt.Scanf("%s", &str)
      if err != nil {
        return err
      }
      ekey, err := EkeyDecode(str)
      if err != nil {
        return err
      }
      fmt.Printf("%s\n", ekey.YAMLEncode())
      return nil
    },
  }
  return cmd
}
