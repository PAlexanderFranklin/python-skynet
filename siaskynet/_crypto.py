import nacl
import nacl.bindings
import hashlib
from backports.pbkdf2 import pbkdf2_hmac # For generating the a proper 32 byte password from the seed

class KeyPair:
	def __init__(self, publicKey:str, privateKey:str):
		self.publicKey = publicKey
		self.privateKey = privateKey

def genKeyPairFromSeed(seed:str) -> KeyPair:
	"""
	Generates a public and private key from a provided, secure seed.
	Args:
		seed(str): Any random seed can be used. Make sure to remember the seed so that you
		can re-generate the public and private keys if your ever lose them.
	Returns:
		KeyPair: The generated key pair.
	Throws:
		Will throw if the input is not a string.
	"""
	if not isinstance(seed, str):
		raise Exception("The seed value has to be a string")

	seed = seed.encode("utf-8") 								# <---- Not in typescript code.
	key = pbkdf2_hmac("sha256", seed, "", 1000, 32 * 8)
	return KeyPair(nacl.bindings.crypto_sign_seed_keypair(key))
	# TypeScript Code
  # const derivedKeyHex = codec.hex.fromBits(derivedKey);
  # const { publicKey, secretKey } = sign.keyPair.fromSeed(hexToUint8Array(derivedKeyHex));
  # return { publicKey: toHexString(publicKey), privateKey: toHexString(secretKey) };