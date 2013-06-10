from addresses import *
from Crypto.Cipher import AES
from Crypto import Random

#key: 32 bytes

#BETA LENGHT
#eid: 4 bytes
#mask: 4 bytes
#xtr_id: 16 bytes
#tS: 8 bytes
#otp: 32 bytes
#ack: 16 bytes

#TOTAL BETA 80 bytes

class Beta(object):
  def __init__ (self, eid,mask=32,xtr_id=b'1234567890123456',ts=b'12345678', otp=b'asdfghjkla123456asdfghjkla123456',ack=b'ackACKackACK9999'):
    self.eid = IPAddr(eid)
    self.mask = struct.pack('>I', mask)
    self.xtr_id = xtr_id
    self.ts = ts
    self.otp = otp
    self.ack = ack
    print 'Beta PLAIN: ', self.ack
    return
    
  def encrypt(self, key = b'Sixteen byte keySixteen byte key'):
    self.key = key
    #print "Key:", ("".join("{0:02x}".format(ord(c)) for c in key))
    self.iv = Random.new().read(AES.block_size)
    cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    
    self.ciphertext = cipher.encrypt(self.toRaw())
    #self.ciphertext = cipher.encrypt(b'asds')
    return self.iv+self.ciphertext
  
  def decrypt(self, rcvd_ciphertext, key = b'Sixteen byte keySixteen byte key'):
    self.key = key
    self.iv = rcvd_ciphertext[0:16]
    self.ciphertext = rcvd_ciphertext[16:]
    cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    rcvd = cipher.decrypt(self.ciphertext)
    
    self.eid = IPAddr(struct.unpack(">L", rcvd[:4])[0])
    self.mask = struct.unpack(">L", rcvd[4:8])[0]
    self.xtr_id = rcvd[8:24]
    self.ts = rcvd[24:32]
    self.otp = rcvd[32:64]
    self.ack = rcvd[64:]
    print 'EID accepted', self.eid.toStr()
    print 'Mask accepted %s' % (self.mask)
    print "xTR accepted: %s" % (self.xtr_id)
    print 'TS accepted: %s' % (self.ts)
    print 'OTP received: %s' % (self.otp)
    print 'ACK received: %s' % (self.ack)
  
  def toRaw(self):
    return self.eid.toRaw()+self.mask+self.xtr_id+self.ts+self.otp+self.ack