from main2 import key_gen, pk_from_sk

p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 -1
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

K = GF(p)
C = EllipticCurve(K, [ a, b ])
BTC_EC_FIXED_POINT = C.point((Gx, Gy))


####################################################################################
# TEST CASES Bitcoin key generation
####################################################################################

(sk,pk)= key_gen()

if (str(type(sk)) == '<type \'sage.rings.integer.Integer\'>'):
    print ("Test 1.1 True")
else:
    print ("Test 1.1 False: Secret key variable does not have a correct type.")

if ( str(type(pk)) == '<class \'sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field\'>'):
    print ("Test 1.2 True")
else:
    print ("Test 1.2 False: Public key variable does not have a correct type.")



####################################################################################
# TEST CASES Bitcoin public key computation
####################################################################################

SK = 0xa7fdb283e6f17cae5cc528dede844693833b01901da4565c0f720d243808456
PK = pk_from_sk(SK)

exp_PK = C.point((102932110615030912195251714675399137743967004457752232542823874303141694029081, 50595351503105113425370052851377959471829273805383542424721209405607880519256))

print ("Test 2.1", PK == exp_PK)

SK = 0x52c9f61de317a5775cfb739fb0b2a8be272c50fd3f12d4759c69d258428b00bf
PK = pk_from_sk(SK)

exp_PK = C.point((54437664866244252025592075707005352202084641410804777694752336694468431883643, 68945548390797962169466413067814862457806470235695926355975243061659496318512))

print ("Test 2.2", PK == exp_PK)

####################################################################################
# TEST CASES Bitcoin WIF private key export
####################################################################################

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = False)

exp_wif = '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'

print ("Test 3.1", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = True)

exp_wif = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ'

print ("Test 3.2", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = False)

exp_wif = '91pPmKypfMGxN73N3iCjLuwBjgo7F4CpGQtFuE9FziSieVTY4jn'

print ("Test 3.3", wif == exp_wif)

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = True)

exp_wif = 'cNcBUemoNGVRN9fRtxrmtteAPQeWZ399d2REmX1TBjvWpRfNMy91'

print ("Test 3.4", wif == exp_wif)

####################################################################################
# TEST CASES Bitcoin get address
####################################################################################

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', False)

exp_address = '1thMirt546nngXqyPEz532S8fLwbozud8'

print ("Test 4.1", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', False)

exp_address = 'mgQeemwrt5Y3Zo1TgxDMtxEkzeweW3gXAg'

print ("Test 4.2", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', True)

exp_address = '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'

print ("Test 4.3", address == exp_address)

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', True)

exp_address = 'mj8v7r8KzDyoHK9rpdQtHYq6piRVCKpVSV'

print ("Test 4.4", address == exp_address)