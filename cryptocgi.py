from Crypto.Cipher import AES
from Crypto.Cipher import AES
import base64
import os

print "Hello"

def encryption(privateInfo):
	BLOCK_SIZE=16 #16x8=128 bits
	PADDING='('

	pad=lambda s:str((BLOCK_SIZE - len(s) % BLOCK_SIZE) + PADDING)

	EncodeAES = lambda c ,s :base64.b64encode(c.encrypt(pad(s)))

	secret = os.urandom(BLOCK_SIZE)
	print "encryption key:",secret

	cipher = AES.new(secret)

	encoded=EncodeAES(cipher , privateInfo)
	encoded=str(encoded)

	print "Encrypted string :",encoded

a=raw_input("Enter a message to encrypt:")
encryption(a)
