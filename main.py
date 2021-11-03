typeset_mode(True, display=False)

import hashlib
import random

#########################################################################################
# 
# BITCOIN PARAMETER VALUES
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


#########################################################################################
#
# BITCOIN FUNCTIONS
#
#########################################################################################

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
    #encode v, which is a string of bytes, to base58.
          
	long_value = 0
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
    #decode v into a string of len bytes

	long_value = 0
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
# BITCOIN KEY & ADDRESS GENERATOR
#
#########################################################################################

# Bitcoin key generation
#
# Function key_gen()
# 
#
    
def key_gen():
    """
    Function that generates a key pair (private key / public key) that can be used in the Bitcoin system. 
    The function does not receive any input parameters and generates a random private key
    
    Returns 
    --------
    keys[0] : int 
        The private key and will be represented as an integer of the ring in which the secp256k1 curve works
    keys[1] : C.point
        The public key and will be represented as a point of the elliptic curve
    """
    
    keys = []

    #Generator Point
    G = C.point((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
    
    #secret key
    sk = ZZ.random_element(n)
    keys.append(sk)
    
    #public key
    K = sk * G
    
    keys.append(K)

    return keys



# Bitcoin public key computation

def pk_from_sk(sk):
    """
    A function that generates a public key from a private key. 
    The function receives the private key (SK) as a parameter. 
    
    Attributes
    -------
    sk : C.point
        The secret key

    Returns
    -------
    pk : C.point
        The public key represented as a point of the elliptic curve secp256k1
    """    
    #Generator Point
    G = C.point((0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
    
    #public key
    pk = sk * G

    return pk



# Bitcoin WIF private key export
#

def sk_to_wif(sk, network, compressed):
    
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
    
    return wif



# Bitcoin get address
#
# Function get_address(pk, network)
# 
#

def get_address(pk, network, compressed):
    
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
    
    
    return address

