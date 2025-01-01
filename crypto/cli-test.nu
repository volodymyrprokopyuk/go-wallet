#!/usr/bin/env nu

use std assert

$env.PATH = $env.PATH | prepend ("." | path expand)

def "test hash sha256" [] {
  let cases = [[data, exp];
    ["message", "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d"],
    [0x[1a2b], "7bb58a59efd43e747eaf28bbd8fc2d66fb0786b5fbecb617341aa018919ea42d"]
  ]
  $cases | each {|c|
    let hash = $c.data | wallet hash sha256
    assert equal $hash $c.exp
    let exp = $c.data | openssl dgst -sha256 -binary | encode hex --lower
    assert equal $hash $exp
  }
}

def "test hash keccak256" [] {
  let cases = [[data, exp];
    ["message", "c2baf6c66618acd49fb133cebc22f55bd907fe9f0d69a726d45b7539ba6bbe08"],
    [0x[1a2b], "976ea750014b2010e9adf291796e3612009fe1aace333e7affcd7690a0fcafb6"]
  ]
  $cases | each {|c|
    let hash = $c.data | wallet hash keccak256
    assert equal $hash $c.exp
    let exp = $c.data | openssl dgst -keccak-256 -binary | encode hex --lower
    assert equal $hash $exp
  }
}

def "test mac hmac-sha512" [] {
  let cases = [[data, key, exp];
    ["message", "key",
     "e477384d7ca229dd1426e64b63ebf2d36ebd6d7e669a6735424e72ea6c01d3f8b56eb39c36d8232f5427999b8d1a3f9cd1128fc69f4d75b434216810fa367e98"],
    [0x[1a2b], "key",
     "a0355072d81e01f3c5750d7af58299581d84c1938428284e0037e173bcb74c40229e674ce4598767b3faa1f83fc2cfa96e374959b57c11c888456e0aeafd12b9"]
  ]
  $cases | each {|c|
    let mac = $c.data | wallet mac hmac-sha512 --key $c.key
    assert equal $mac $c.exp
    let exp = $c.data | openssl dgst -sha512 -hmac $c.key -binary
      | encode hex --lower
    assert equal $mac $exp
  }
}

def "test kdf pbkdf2-sha512" [] {
  let cases = [[pass, salt, iter, keyLen, exp];
    ["pass", "salt", 2048, 64,
     "6c6443ef774e4aed18d455e1f3e0cdd1342aa67cf26c19270a208d9599740495784c406ac54f1b4fc8139692830c3f96ad2eaf331fb4ab4eaa0aff27501e09a4"]
  ]
  $cases | each {|c|
    let key = $c.pass | (wallet kdf pbkdf2-sha512 --salt $c.salt
      --iter $c.iter --keylen $c.keyLen)
    assert equal $key $c.exp
    let pass = $c.pass | encode hex --lower
    let salt = $c.salt | encode hex --lower
    let exp = (openssl kdf -kdfopt digest:sha512 -kdfopt iter:($c.iter)
      -kdfopt hexpass:($pass) -kdfopt hexsalt:($salt)
      -keylen $c.keyLen -binary pbkdf2) | encode hex --lower
    assert equal $key $exp
  }
}

def "test base58check encode decode" [] {
  let cases = [[num, str];
    ["a5d573ecb2d798d4de357e599271f13169ce0c68d4",
     "29jEAGMrL2xNdPrYF69tTdDJxa1PnkUtoK6"]
    ["0000a5d573ecb2d798d4de357e599271f13169ce0c68d4",
     "1129jEAGMrL2xNdPrYF69tTdDJxa1PnkUtoK6"]
  ]
  $cases | each {|c|
    let str = $c.num | wallet base58check encode
    assert equal $str $c.str
    let num = $c.str | wallet base58check decode
    assert equal $num $c.num
    assert error { $c.str + "x" | wallet base58check decode }
  }
}

test hash sha256
test hash keccak256
test mac hmac-sha512
test kdf pbkdf2-sha512
test base58check encode decode

print success
