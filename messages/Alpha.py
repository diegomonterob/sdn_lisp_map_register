from addresses import *
from Crypto.Cipher import AES
from Crypto import Random

#key: 32 bytes


#ALPHA LENGHT
#eid: 4 bytes
#mask: 4 bytes
#xtr_id: 16 bytes
#tS: 8 bytes

#TOTAL ALPHA 32 bytes

class Alpha(object):
  def __init__ (self, eid,mask=32,xtr_id = b'1234567890123456',ts = b'12345678'):
    self.eid = IPAddr(eid)
    self.mask = struct.pack('>I', mask)
    self.xtr_id = xtr_id
    self.ts = ts
    return
    
  def encrypt(self,key = b'Sixteen byte keySixteen byte key'):
    self.key = key
    print '*** Encrypt Key [EID %s] = %s'% (self.eid.toStr(), self.key)
    #print "Key:", ("".join("{0:02x}".format(ord(c)) for c in key))
    self.iv = Random.new().read(AES.block_size)
    cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    print "EID in Alpha:", (":".join("{0:02x}".format(ord(c)) for c in self.eid.toRaw()))
    print "EID-mask in Alpha:", (":".join("{0:02x}".format(ord(c)) for c in self.mask))
    self.ciphertext = cipher.encrypt(self.toRaw())
    #self.ciphertext = cipher.encrypt(b'asds')
    return self.iv+self.ciphertext
  
  def decrypt(self, rcvd_ciphertext, key = b'Sixteen byte keySixteen byte key'):
    self.key = key
    print '*** DEncrypt Key [EID %s] = %s'% (self.eid.toStr(), self.key)
    self.iv = rcvd_ciphertext[0:16]
    self.ciphertext = rcvd_ciphertext[16:]
    cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
    rcvd = cipher.decrypt(self.ciphertext)
    print "alpha received:", (":".join("{0:02x}".format(ord(c)) for c in rcvd))
    self.eid = IPAddr(struct.unpack(">L", rcvd[:4])[0])
    self.mask = struct.unpack(">L", rcvd[4:8])[0]
    self.xtr_id = rcvd[8:24]
    self.ts = rcvd[24:]
    print 'EID received', self.eid.toStr()
    print 'Mask received %s' % (self.mask)
    print "xTR_id received: %s" % (self.xtr_id)
    print 'TS received: %s' % (self.ts)
    
  def toRaw(self):
    return self.eid.toRaw()+self.mask+self.xtr_id+self.ts    