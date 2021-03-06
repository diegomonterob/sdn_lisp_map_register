from addresses import *
from Crypto.Cipher import AES
from Crypto import Random

class Gamma(object):
     
  def __init__ (self, eid, mask=32, ts=0, ack=0, otp=0):
    self.eid = IPAddr(eid)
    self.mask = struct.pack('>I', mask)
    self.ts = ts
    self.ack = ack
    self.otp = otp
    return
    
  def encrypt(self):
    
    self.iv = Random.new().read(AES.block_size)
    cipher = AES.new(self.otp, AES.MODE_CBC, self.iv)
    
    self.ciphertext = cipher.encrypt(self.toRaw())
    #self.ciphertext = cipher.encrypt(b'asds')
    return self.iv+self.ciphertext
  
  def decrypt(self, rcvd_ciphertext):
    
    self.iv = rcvd_ciphertext[0:16]
    self.ciphertext = rcvd_ciphertext[16:]
    cipher = AES.new(self.otp, AES.MODE_CBC, self.iv)
    rcvd = cipher.decrypt(self.ciphertext)
    
    self.eid = IPAddr(struct.unpack(">L", rcvd[:4])[0])
    self.mask = struct.unpack(">L", rcvd[4:8])[0]
    self.ts = rcvd[8:16]
    self.acl = rcvd[16:]
    print 'Gamma EID', self.eid.toStr()
    print 'Gamma Mask %s' % (self.mask)
    print 'Gamma TS: %s' % (self.ts)
    print 'Gamma ACK: %s' % (self.ack)
  
  def toRaw(self):
    return self.eid.toRaw()+self.mask+self.ts+self.ack