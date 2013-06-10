from Crypto.Cipher import AES
from Crypto import Random


key = b'Sixteen byte keySixteen byte key'
print "Key:", ("".join("{0:02x}".format(ord(c)) for c in key))
iv = Random.new().read(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, iv)
#msg = iv + cipher.encrypt(b'Attack at dawnuu')
#print "IV + cipher:", ("".join("{0:02x}".format(ord(c)) for c in msg))
print "IV:", ("".join("{0:02x}".format(ord(c)) for c in iv))
ciphertext = cipher.encrypt(b'Attack at dawnuuAttack at dawnuuAttack at dawnuuAttack at dawnuu')
print "encrypted message:", ("".join("{0:02x}".format(ord(c)) for c in ciphertext))
#print "encrypted message:", (":".join("{0:02x}".format(ord(c)) for c in ciphertext))
cipher = AES.new(key, AES.MODE_CBC, iv)
plain=cipher.decrypt(ciphertext)
print "decrypted message:", plain