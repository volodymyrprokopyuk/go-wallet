#!/usr/bin/env nu

use std assert

$env.PATH = $env.PATH | prepend ("." | path expand)

def parse-key [keyName: string]: string -> string {
  let strKey = $in
  let hexKey = $strKey | lines | skip until { $in =~ $keyName } | skip 1
    | take while { $in =~ '^\s+' } | str join
    | str replace --all --regex '[\s:]' ""
  $hexKey
}

def "test key generate" [] {
  let $key = wallet key generate | from yaml
  let $exp = $key.prv | wallet key derive | from yaml
  assert equal $key $exp
}

def "test key derive" [] {
  let prvPEM = openssl ecparam -genkey -name secp256k1 -noout
  let pubPEM = $prvPEM | openssl ec -pubout
  let exp = {
    prv: ($prvPEM | openssl ec -text -noout | parse-key "priv:")
    pub: ($pubPEM | openssl ec -text -noout -pubin | parse-key "pub:"
      | str substring 2..129)
  }
  let key = $exp.prv | wallet key derive | from yaml
  assert equal $key $exp
}

def "test key address" [] {
  let cases = [[prv, exp];
    ["c8aee432ef2035adc6f71a7094c0677eedf74a04f4e17227fa1a4155ad511047",
     "9cea81b9d2e900d6027125378ee2ddfa15feeed1"],
    ["14331ff79e696ae342ca0eab1b2e0f8bd83c4225e3da75cb3d649d443ac860bb",
     "75d28c27ac5c5de118508fee2d14ef5fb04c5435"]
  ]
  $cases | each {|c|
    let key = $c.prv | wallet key derive | from yaml
    let addr = $key.pub | wallet key address
    assert equal $addr $c.exp
  }
}

def "test address encode" [] {
  let cases = [[exp];
    ["9cea81B9D2E900d6027125378ee2ddfA15FeEED1"],
    ["75D28c27aC5C5de118508fee2d14ef5FB04c5435"]
  ]
  $cases | each {|c|
    let addr = $c.exp | str downcase | wallet address encode
    assert equal $addr $c.exp
  }
}

def "test address verify" [] {
  let cases = [[addr, exp];
    ["9cea81B9D2E900d6027125378ee2ddfA15FeEED1", true],
    ["9cea81B9D2E900d6027125378ee2ddfA15FeEEd1", false],
    ["75D28c27aC5C5de118508fee2d14ef5FB04c5435", true],
    ["75D28c27aC5C5de118508fee2d14ef5FB04C5435", false]
  ]
  $cases | each {|c|
    let valid = $c.addr | wallet address verify | into bool
    assert equal $valid $c.exp
  }
}

let seeds = [[seed, bits, mnemonic];
  ["0c1e24e5917779d297e14d45f14e1a1a", 128,
   "army van defense carry jealous true garbage claim echo media make crunch"],
  ["2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c", 256,
   "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige"]
]

def "test seed generate" [] {
  let cases = [[seed, bits, exp];
    [$seeds.0.seed, $seeds.0.bits, $seeds.0.mnemonic],
    [$seeds.1.seed, $seeds.1.bits, $seeds.1.mnemonic]
  ]
  $cases | each {|c|
    let mnemonic = $c.seed | wallet seed generate --bits $c.bits --stdin
    assert equal $mnemonic $c.exp
  }
}

def "test seed verify" [] {
  let cases = [[mnemonic, exp];
    [$seeds.0.mnemonic, true],
    [($seeds.0.mnemonic | str replace "true" "van"), false],
    [$seeds.1.mnemonic, true],
    [($seeds.1.mnemonic | str replace "top" "van"), false]
  ]
  $cases | each {|c|
    let valid = $c.mnemonic | wallet seed verify | into bool
    assert equal $valid $c.exp
  }
}

def "test seed derive" [] {
  let cases = [[mnemonic, passphrase, exp];
    [$seeds.0.mnemonic, "",
     "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570"],
    [$seeds.0.mnemonic, "passphrase",
     "a72c0c6976113d8fff342a96041d68e1a8f79a465ae8aa980aba349339965cb8e068a3945a90e7ee9cda6a5d9b3a1df317afb0a73a9c50c7fbe0a514a6fa651d"],
    [$seeds.1.mnemonic, "",
     "3269bce2674acbd188d4f120072b13b088a0ecf87c6e4cae41657a0bb78f5315b33b3a04356e53d062e55f1e0deaa082df8d487381379df848a6ad7e98798404"]
    [$seeds.1.mnemonic, "passphrase",
     "575385ded4e59bcb0dff46d376faf9d6839eecfde301a3e0f5065d417162a011d3fdb8f1371ea33db10222e5c0d34afd5e0050ff230302411d7f250f71f642b3"]
  ]
  $cases | each {|c|
    let seed = $c.mnemonic | wallet seed derive --passphrase $c.passphrase
    assert equal $seed $c.exp
  }
}

test key generate
test key derive
test key address

test address encode
test address verify

test seed generate
test seed verify
test seed derive

print success
