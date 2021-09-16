# Bitcoin-key-generator

The goal of this project is to create the necessary functions to generate Bitcoin keys, both public and private, and calculate their corresponding addresses. It will also allow us to generate private keys in WIF format that can be imported into standard wallets

![Public key to bitcoin address](./img/BitcoinAddress.png "Public key to bitcoin address")

Public key to bitcoin address: conversion of a public key into a bitcoin address. 
From [Mastering Bitcoin: Programming the Open Blockchain](https://bitcoinbook.info/)

## Key pair generation function

Function that generates a key pair (private key / public key) that can be used in the Bitcoin system. The function does not receive any input parameters and generates a random private key. The function returns a two value vector:
 * The first value will be the private key and will be represented as an integer of the ring in which the _secp256k1_ curve works
 * The second value of the vector will be the public key and will be represented as a point of the elliptic curve

```python
def key_gen():
```

 ## Public key generation function

 A function that generates a public key from a private key. The function receives the private key (SK) as a parameter. The function will return the public key represented as a point of the elliptic curve _secp256k1_

 ```python
def pk_from_sk(sk):
```

## Private key export function

Function that converts a private key in [WIF](https://en.bitcoin.it/wiki/Wallet_import_format) format. The function receives three input parameters:
* The private key to convert
* The network for which you want to export the key (which can be MAINET or TESTNET)
* A boolean (True / False) that will indicate whether the export is to be done in compressed mode or not
The function returns the value of the private key in [WIF](https://en.bitcoin.it/wiki/Wallet_import_format) format

 ```python
def sk_to_wif(sk, network, compressed):
```

## Bitcoin address generation function

Function that generates a P2PKH Bitcoin address from a public key. The function will receive three input parameters:
* The public key
* The network for which you want to generate the address (which can be MAINET or TESTNET)
* A boolean (True / False) that will indicate whether the export is to be done in compressed mode or not
The function returns the address

 ```python
def get_address(pk, network, compressed):
```