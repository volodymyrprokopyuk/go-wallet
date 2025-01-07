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
  let pemPrv = openssl ecparam -genkey -name secp256k1 -noout
  let pemPub = $pemPrv | openssl ec -pubout
  let exp = {
    prv: ($pemPrv | openssl ec -text -noout | parse-key "priv:")
    pub: ($pemPub | openssl ec -text -noout -pubin | parse-key "pub:")
  }
  let key = $exp.prv | wallet key derive | from yaml | select prv pub
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
    ["75D28c27aC5C5de118508fee2d14ef5FB04c5435"],
    ["5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"],
    ["8617E340B3D01FA5F11F306F4090FD50E238070D"],
    ["27b1fdb04752bbc536007a920d24acb045561c26"]
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

let seeds = [[seed, bits, mnem];
  ["0c1e24e5917779d297e14d45f14e1a1a", 128,
   "army van defense carry jealous true garbage claim echo media make crunch"],
  ["2041546864449caff939d32d574753fe684d3c947c3346713dd8423e74abcf8c", 256,
   "cake apple borrow silk endorse fitness top denial coil riot stay wolf luggage oxygen faint major edit measure invite love trap field dilemma oblige"]
]

def "test mnemonic generate" [] {
  [128, 160, 192, 224, 256] | each {|bits|
    let mnem = wallet mnemonic generate --bits $bits
    let valid = $mnem | wallet mnemonic verify | into bool
    assert equal $valid true
  }
}

def "test mnemonic derive" [] {
  let cases = [[seed, bits, exp];
    [$seeds.0.seed, $seeds.0.bits, $seeds.0.mnem],
    [$seeds.1.seed, $seeds.1.bits, $seeds.1.mnem]
  ]
  $cases | each {|c|
    let mnem = $c.seed | wallet mnemonic derive --bits $c.bits
    assert equal $mnem $c.exp
  }
}

def "test mnemonic verify" [] {
  let cases = [[mnem, exp];
    [$seeds.0.mnem, true],
    [($seeds.0.mnem | str replace "true" "van"), false],
    [$seeds.1.mnem, true],
    [($seeds.1.mnem | str replace "top" "van"), false]
  ]
  $cases | each {|c|
    let valid = $c.mnem | wallet mnemonic verify | into bool
    assert equal $valid $c.exp
  }
}

def "test hd seed" [] {
  let cases = [[mnem, pass, exp];
    [$seeds.0.mnem, "",
     "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570"],
    [$seeds.0.mnem, "passphrase",
     "a72c0c6976113d8fff342a96041d68e1a8f79a465ae8aa980aba349339965cb8e068a3945a90e7ee9cda6a5d9b3a1df317afb0a73a9c50c7fbe0a514a6fa651d"],
    [$seeds.1.mnem, "",
     "3269bce2674acbd188d4f120072b13b088a0ecf87c6e4cae41657a0bb78f5315b33b3a04356e53d062e55f1e0deaa082df8d487381379df848a6ad7e98798404"]
    [$seeds.1.mnem, "passphrase",
     "575385ded4e59bcb0dff46d376faf9d6839eecfde301a3e0f5065d417162a011d3fdb8f1371ea33db10222e5c0d34afd5e0050ff230302411d7f250f71f642b3"]
  ]
  $cases | each {|c|
    let seed = $c.mnem | wallet hd seed --passphrase $c.pass
    assert equal $seed $c.exp
  }
}

def "test hd master" [] {
  let cases = [{
    mnem: $seeds.0.mnem,
    prv: "b2a0d576b828b537688b561f2cfa8dac3602d54c62bde619ad5331e6c235ee26",
    pubc: "03ca72b45eede592f059b7eaf3da13eb7d8d15aa472b6f79f74820bb22ff596186",
    code: "b70d675323c40ec461e0a6af603b1f135fb2af9ae753eeff18922732a73b0f05",
    xprv: "xprv9s21ZrQH143K3t4UZrNgeA3w861fwjYLaGwmPtQyPMmzshV2owVpfBSd2Q7YsHZ9j6i6ddYjb5PLtUdMZn8LhvuCVhGcQntq5rn7JVMqnie",
    xpub: "xpub661MyMwAqRbcGN8wfsuh1Hzfg7rAMCGBwVsNCGpawhJykVpBMUp5Cym6shGYvy5RwATVHgF4vfEqvLFHQeccQtSQcVDvHhhaNB1iFF1gW8e"
  }, {
    mnem: $seeds.1.mnem,
    prv: "fb71fec531b94df06bdcf2cb54b921602adbb65936d71e35ab0dba48e11ff1bb",
    pubc: "03d33a807e3267c95f76d75de4785e118a5a5899ab041f2306a6b30afdedb645f2",
    code: "3d67c4007a39b19fa607c98eeabeb8b8af71bf698eb3afe9e24137794309663b",
    xprv: "xprv9s21ZrQH143K2fpGDeSiVghhRbX6YY7yUZ78Ng644PevUa8YKHAYJAg9CCbzkXdZvKZ8Xevajm9rcfYU974Ed86rFzvE58Yq8DdYuAZso5d",
    xpub: "xpub661MyMwAqRbcF9tjKfyirpeRydMawzqpqn2jB4VfcjBuMNTgrpUnqxzd3VGo5xg35qNWx3Mv8veouvNfBj4o32JFW8mFkPruoFTgnRVXSQf"
  }]
  $cases | each {|c|
    let exp = [prv, pubc, code, xprv, xpub]
    let key = $c.mnem | wallet hd seed | wallet hd master
      | from yaml | select ...$exp
    assert equal $key ($c | select ...$exp)
  }
}

def "test hd private decode" [] {
  let cases = [{
    mnem: $seeds.0.mnem, dep: 0, idx: 0,
    prv: "5436c97cfb761b414e0f20c4801d5c4fc4d602a94e4bdaee058890f75c77f756",
    pubc: "0261eb369da972add92ed21fd3d049689700c9a84582181a6ec286ee3f7b5cbc81",
    code: "a74b758d3dc442f8620a2438f56629e62a743a4b4fe1ad02166185bf290b56d1",
    xprv: "xprv9tKxXKXJXn1LoBYH6pXLttdMDHMhtUMeXHDENWJozs6hDbJTxNRttSNLhce18jVdTbYBE184EqHWfvnxqLLctJFKFVuynwk1TQw1eM1x1x2",
    xpub: "xpub67KJvq4CN9Ze1fckCr4MG2a5mKCCHw5VtW8qAtiRZCdg6PdcVuk9SEgpYsmoeTbyd1RorJNCHwxd5phXTQFmQ3bMX7zzvBA8cWVhEpKXkn7"
  }, {
    mnem: $seeds.1.mnem, dep: 0, idx: 1,
    prv: "6081569494472cefe9cab81c0a8821d8cda6cd5ee175e61e21b3c9cc28f1cbb2",
    pubc: "033706dbc981daba489907e63a70eacc61cf7a8bf79a3519148fbb3c3a1ef168a9",
    code: "c8b8af95f08ed822118491ef52bb476763a3a1e5ad971aaaf4edb59457948a96",
    xprv: "xprv9sCE2VB8kwF5Ww36VHTQf859DXoM7msXWonJiQUCMdfkrNghN1EH5qycwXfuCnS82Tij8WFYeJWWeAdfmJJB64uBFTWRS8jtXtKqDpUcJds",
    xpub: "xpub66BaRzi2bJoNjR7ZbJzR2G1smZdqXEbNt2huWnsouyCjjB1quYYXdeJ6npL9K1z4G3M4E8cP3yJf5ZGNQjspAutFvYcHUyzjTo3avhJPwuy"
  }]
  $cases | each {|c|
    let exp = [prv, pubc, code, xprv, xpub]
    let mst = $c.mnem | wallet hd seed | wallet hd master | from yaml
    let prve = $mst.prv ++ $mst.code
    let key = $prve | wallet hd private --depth $c.dep --index $c.idx
      | from yaml | select ...$exp
    assert equal $key ($c | select ...$exp)
    let prv = $key.xprv | wallet hd decode | from yaml | select ...$exp
    assert equal $prv ($c | select ...$exp)
    let pubExp = [pubc, code, xpub]
    let pub = $key.xpub | wallet hd decode | from yaml | select ...$pubExp
    assert equal $pub ($c | select ...$pubExp)
  }
}

def "test hd hardened" [] {
  let cases = [{
    mnem: $seeds.0.mnem, dep: 0, idx: 0,
    prv: "b002c1c5b7c3a9937c08e468fa0fba20ddd8a31a07deddf1464ac160fe9bd334",
    pubc: "03710e0c1ae16fae2bce576c02c90345dec9a2acf0506e32ec24cd37a5e9019a17",
    code: "ce62c620b7cd66e27f970d0f29e4f2082c6b7740bd184d0c9c61f79d819af563",
    xprv: "xprv9tKxXKXSsSYJyrQJ2LAf7wVTsEKqrTJWDXMA4HVEkmyinuAk8vd7caZwPSZFj115zSW922yXMPKLZc3NoxRgiTriYZCWKtDuXcQft8pcsj9",
    xpub: "xpub67KJvq4Lhp6cCLUm8MhfV5SCRGALFv2MakGkrftrK7WhfhVtgTwNANtREj43DgidDyU6HmvT8K8Z88qyA3mVgKec6kECm2S8BipUWDXjzgL"
  }, {
    mnem: $seeds.1.mnem, dep: 0, idx: 1,
    prv: "0500fc8817b8f41d98dd78a095f2336d1a00fa0562ce997e3840a50bf4db0c55",
    pubc: "025650e0339b0bfdaea2550b36ddf0df7cd0f26aaf224fbde16a39f39618777827",
    code: "0e93a5fa7850095f029ae4a4393929dbbad0a05ec907bacd8a646653c18f2d01",
    xprv: "xprv9sCE2VBH6bn3fMqVhMm432W3ZbQSXbYWXqJAcf6CVp1x58fVWZTHijGcsFF7skSAut7Y84UAoF6xzdpmCu1b2v3rqNLyq6hoQDjxyZaL7hz",
    xpub: "xpub66BaRziAvyLLsquxoPJ4QASn7dEvw4GMu4DmR3Vp49Yvwvze46mYGXb6iWthKqB11KAAmWCZmefBWPpQhSTpqRgEgJZCtKHgVJJ9GBRMcWp"
  }]
  $cases | each {|c|
    let exp = [prv, pubc, code, xprv, xpub]
    let mst = $c.mnem | wallet hd seed | wallet hd master | from yaml
    let prve = $mst.prv ++ $mst.code
    let key = $prve | wallet hd hardened --depth $c.dep --index $c.idx
      | from yaml | select ...$exp
    assert equal $key ($c | select ...$exp)
  }
}

def "test hd public" [] {
  let cases = [{
    mnem: $seeds.0.mnem, dep: 0, idx: 0,
    prv: "5436c97cfb761b414e0f20c4801d5c4fc4d602a94e4bdaee058890f75c77f756",
    pubc: "0261eb369da972add92ed21fd3d049689700c9a84582181a6ec286ee3f7b5cbc81",
    code: "a74b758d3dc442f8620a2438f56629e62a743a4b4fe1ad02166185bf290b56d1",
    xpub: "xpub67KJvq4CN9Ze1fckCr4MG2a5mKCCHw5VtW8qAtiRZCdg6PdcVuk9SEgpYsmoeTbyd1RorJNCHwxd5phXTQFmQ3bMX7zzvBA8cWVhEpKXkn7"
  }, {
    mnem: $seeds.1.mnem, dep: 0, idx: 1,
    prv: "6081569494472cefe9cab81c0a8821d8cda6cd5ee175e61e21b3c9cc28f1cbb2",
    pubc: "033706dbc981daba489907e63a70eacc61cf7a8bf79a3519148fbb3c3a1ef168a9",
    code: "c8b8af95f08ed822118491ef52bb476763a3a1e5ad971aaaf4edb59457948a96",
    xpub: "xpub66BaRzi2bJoNjR7ZbJzR2G1smZdqXEbNt2huWnsouyCjjB1quYYXdeJ6npL9K1z4G3M4E8cP3yJf5ZGNQjspAutFvYcHUyzjTo3avhJPwuy"
  }]
  $cases | each {|c|
    let exp = [pubc, code, xpub]
    let mst = $c.mnem | wallet hd seed | wallet hd master | from yaml
    let prve = $mst.prv ++ $mst.code
    let key = $prve | wallet hd private --depth $c.dep --index $c.idx
      | from yaml | select ...$exp
    assert equal $key ($c | select ...$exp)
    let pube = $mst.pubc ++ $mst.code
    let pub = $pube | wallet hd public --depth $c.dep --index $c.idx
      | from yaml | select ...$exp
    assert equal $pub $key
  }
}

test key generate
test key derive
test key address

test address encode
test address verify

test mnemonic generate
test mnemonic derive
test mnemonic verify

test hd seed
test hd master
test hd private decode
test hd hardened
test hd public

print success

# let mst = $seeds.0.mnem | wallet hd seed | wallet hd master | from yaml
# let prve = $mst.prv ++ $mst.code
# let ekey = $prve | wallet hd private --depth 0 --index 0 | from yaml
# $ekey | print
# $ekey.xprv | wallet hd decode | from yaml | print
# $ekey.xpub | wallet hd decode | from yaml | print

# $prve | wallet hd hardened --depth 0 --index 1 | from yaml | print
# let pube = $mst.pubc ++ $mst.code
# $pube | wallet hd public --depth 0 --index 1 | from yaml | print
