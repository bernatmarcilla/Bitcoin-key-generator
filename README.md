# Bitcoin-key-generator

The goal of this project is to create the necessary functions to generate Bitcoin keys, both public and private, and calculate their corresponding addresses. It will also allow us to generate private keys in WIF format that can be imported into standard wallets

## Key generation function (key_gen)

Function that generates a key pair (private key / public key) that can be used in the Bitcoin system. The function does not receive any input parameters and generates a random private key. The function returns a two value vector:
 * The first value will be the private key and will be represented as an integer of the ring in which the _secp256k1_ curve works
 * The second value of the vector will be the public key and will be represented as a point of the elliptic curve

 ## Public key retrieval function (pk_from_sk)

 A function that generates a public key from a private key. The function receives the private key (SK) as a parameter. The function will return the public key represented as a point of the elliptic curve _secp256k1_

## Private key export function

Function that converts a private key in [WIF](https://en.bitcoin.it/wiki/Wallet_import_format) format. The function receives three input parameters:
* The private key to convert
* The network for which you want to export the key (which can be MAINET or TESTNET)
* A boolean (True / False) that will indicate whether the export is to be done in compressed mode or not. The function returns the value of the private key in [WIF](https://en.bitcoin.it/wiki/Wallet_import_format) format