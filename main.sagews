typeset_mode(True, display=False)

#########################################################################################
# 
# PUBLIC HELPERS
#
# You can use these functions and definitions in your implementation
#
#########################################################################################

import hashlib
    

def doublehash(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_160(public_key):
 	md = hashlib.new('ripemd160')
	md.update(hashlib.sha256(public_key).digest())
	return md.digest()

def hash_160_to_bc_address(h160, v=None):
	if v==None:
		v = 0  # mainnet network is assumed  
	vh160 = chr(v) + h160
	h = doublehash(vh160)
	addr = vh160 + h[0:4]
	return b58encode(addr)

def public_key_to_bc_address(public_key, v=None):
	if v==None:
		v = 0 # mainnet network is assumed
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160, v)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
	""" 
          encode v, which is a string of bytes, to base58.
          
	"""
	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += (256**i) * ord(c)
        
	result = ''
	while long_value >= __b58base:
		div, mod = divmod(long_value, __b58base)
		result = __b58chars[mod] + result
		long_value = div
	result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression:
	# leading 0-bytes in the input become leading-1s
	nPad = 0
	for c in v:
		if c == '\0': nPad += 1
		else: break

	return (__b58chars[0]*nPad) + result

def b58decode(v, length=None):
	""" 
           decode v into a string of len bytes
           
	"""
	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += __b58chars.find(c) * (__b58base**i)

	result = ''
	while long_value >= 256:
		div, mod = divmod(long_value, 256)
		result = chr(mod) + result
		long_value = div
	result = chr(long_value) + result

	nPad = 0
	for c in v:
		if c == __b58chars[0]: nPad += 1
		else: break

	result = chr(0)*nPad + result
	if length is not None and len(result) != length:
		return None

	return result



#########################################################################################
# 
# BITCOIN PARAMETER VALUES
#
# You can use these definitions in your implementation
#
#########################################################################################

p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 -1
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

K = GF(p)
C = EllipticCurve(K, [ a, b ])
BTC_EC_FIXED_POINT = C.point((Gx, Gy))



# EXERCISE 1: Bitcoin key generation
#
# Function key_gen()
# 
#
import random
    
def key_gen():
    
    keys = []

    #### IMPLEMENTATION GOES HERE ####
    
    #Generator Point
    G = C.point((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
    
    #secret key
    sk = ZZ.random_element(n)
    keys.append(sk)
    
    #public key
    K = sk * G
    
    keys.append(K)


    ##################################

    return keys



# EXERCISE 2: Bitcoin public key computation
#
# Function pk_from_sk()
# 
#

def pk_from_sk(sk):
    
    #### IMPLEMENTATION GOES HERE ####
    
    #Generator Point
    G = C.point((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
    
    #public key
    pk = sk * G

    ##################################

    return pk



# EXERCISE 3: Bitcoin WIF private key export
#

def sk_to_wif(sk, network, compressed):
    
    #### IMPLEMENTATION GOES HERE ####
    
    if (network == 'TESTNET'):
        if (compressed == True): # Add suffix '01' to indicate a compressed private key
            sk ='ef' + str(sk.str(16)) + '01'
        else:
            sk ='ef' + str(sk.str(16))
        sha_sk = doublehash(sk.decode('hex'))
        
        sk = str(sk.decode('hex')) + str(sha_sk[:4])
        wif = b58encode(sk)

    else: 
        if (compressed == True): # Add suffix '01' to indicate a compressed private key
            sk ='80' + str(sk.str(16)) + '01'
        else:
            sk ='80' + str(sk.str(16))
        sha_sk = doublehash(sk.decode('hex'))
        
        sk = str(sk.decode('hex')) + str(sha_sk[:4])
        wif = b58encode(sk)        
    
    ##################################
    
    return wif



# EXERCISE 4: Bitcoin get address
#
# Function get_address(pk, network)
# 
#

def get_address(pk, network, compressed):
    
    #### IMPLEMENTATION GOES HERE ####
    
    x =str(hex(int(pk[0])))
    y =str(hex(int(pk[1])))
        
    last =int(y[-2], 16)
    
    
    if (network == 'TESTNET'):
        if (compressed == True):
            if (last%2==0): #even
                addr = '02' +str(x[2:66])
            else:
                addr = '03' +str(x[2:66])
        else:
             addr = '04' +str(x[2:66]) + str(y[2:66]) 
             
        decoded_addr=addr.decode('hex')
        address = public_key_to_bc_address(decoded_addr, 0x6f)
        
    else:
        if (compressed == True):
            if (last%2==0): #even
                addr = '02' +str(x[2:66])
            else:
                addr = '03' +str(x[2:66])
        else:
             addr = '04' +str(x[2:66]) + str(y[2:66])        
            
        decoded_addr=addr.decode('hex')
        address = public_key_to_bc_address(decoded_addr)
    
    
    ##################################
    
    return address




####################################################################################
# TEST CASES EXERCICE 1
####################################################################################

(sk,pk)= key_gen()

if (str(type(sk)) == '<type \'sage.rings.integer.Integer\'>'):
    print "Test 1.1 True"
else:
    print "Test 1.1 False: Secret key variable does not have a correct type."

if ( str(type(pk)) == '<class \'sage.schemes.elliptic_curves.ell_point.EllipticCurvePoint_finite_field\'>'):
    print "Test 1.2 True"
else:
    print "Test 1.2 False: Public key variable does not have a correct type."

#{"stdout": "Test 1.1 True\nTest 1.2 True"}︡

####################################################################################
# TEST CASES EXERCICE 2
####################################################################################

SK = 0xa7fdb283e6f17cae5cc528dede844693833b01901da4565c0f720d243808456
PK = pk_from_sk(SK)

exp_PK = C.point((102932110615030912195251714675399137743967004457752232542823874303141694029081, 50595351503105113425370052851377959471829273805383542424721209405607880519256))

print "Test 2.1", PK == exp_PK

SK = 0x52c9f61de317a5775cfb739fb0b2a8be272c50fd3f12d4759c69d258428b00bf
PK = pk_from_sk(SK)

exp_PK = C.point((54437664866244252025592075707005352202084641410804777694752336694468431883643, 68945548390797962169466413067814862457806470235695926355975243061659496318512))

print "Test 2.2", PK == exp_PK
#{"stdout": "Test 2.1 True\nTest 2.2 True"}︡

####################################################################################
# TEST CASES EXERCICE 3
####################################################################################

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = False)

exp_wif = '5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn'

print "Test 3.1", wif == exp_wif

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'MAINET', compressed = True)

exp_wif = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ'

print "Test 3.2", wif == exp_wif

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = False)

exp_wif = '91pPmKypfMGxN73N3iCjLuwBjgo7F4CpGQtFuE9FziSieVTY4jn'

print "Test 3.3", wif == exp_wif

sk = 0x1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd
wif = sk_to_wif(sk,'TESTNET', compressed = True)

exp_wif = 'cNcBUemoNGVRN9fRtxrmtteAPQeWZ399d2REmX1TBjvWpRfNMy91'

print "Test 3.4", wif == exp_wif
#{"stdout": "Test 3.1 True\nTest 3.2 True\nTest 3.3 True\nTest 3.4 True"}︡

####################################################################################
# TEST CASES EXERCICE 4
####################################################################################

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', False)

exp_address = '1thMirt546nngXqyPEz532S8fLwbozud8'

print "Test 4.1", address == exp_address

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', False)

exp_address = 'mgQeemwrt5Y3Zo1TgxDMtxEkzeweW3gXAg'

print "Test 4.2", address == exp_address

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'MAINET', True)

exp_address = '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'

print "Test 4.3", address == exp_address

pk = C.point((41637322786646325214887832269588396900663353932545912953362782457239403430124, 16388935128781238405526710466724741593761085120864331449066658622400339362166))

address = get_address(pk,'TESTNET', True)

exp_address = 'mj8v7r8KzDyoHK9rpdQtHYq6piRVCKpVSV'

print "Test 4.4", address == exp_address