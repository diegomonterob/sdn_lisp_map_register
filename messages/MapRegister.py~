from addresses import *
from LISPMessage import *
from M2Crypto import EVP, DSA, util
import struct 


class MapRegister(LISPMessage):
  def __init__ (self, eid, mask, alpha, rloc_sp='0.0.0.0' , xtr_id=b'1234567890123456', ra_sp=b'authorized'):
    self.msg_type = MSG_MAP_REGISTER
    self.eid = IPAddr(eid)		#EID to register
    #self.mask = struct.pack('>I', mask)#EID mask
    self.mask = mask
    print 'Mask in MapRegister ', self.mask
    self.alpha=alpha			#Encrypted alpha only visible for MS
    self.rloc_sp = IPAddr(rloc_sp)	#RLOC Locator for the EID
    self.xtr_id = xtr_id	#xTR Identifier
    self.ra_sp = ra_sp		#RLOC Authorization 
    return
  
  def generateSign(self):
    message = self.toRaw()
    print "GenSign Raw:", (":".join("{0:02x}".format(ord(c)) for c in message))
    md = EVP.MessageDigest('sha1')
    md.update(message)        
    digest = md.final()
    print "GenSign SHA1:", (":".join("{0:02x}".format(ord(c)) for c in digest))
    #print "Mask:", self.mask
    dsa = DSA.load_key("keys/dsa_priv_xtr.pem")
    self.signature = dsa.sign(digest)
    print "GenSign r:", (":".join("{0:02x}".format(ord(c)) for c in self.signature[0]))
    print "GenSign s:", (":".join("{0:02x}".format(ord(c)) for c in self.signature[1]))
    return
  
  def verifySign(self):
    message = self.toRaw()
    print "VerSign Raw:", (":".join("{0:02x}".format(ord(c)) for c in message))
    md = EVP.MessageDigest('sha1')
    md.update(message)        
    digest = md.final()
    print "VerSign SHA1:", (":".join("{0:02x}".format(ord(c)) for c in digest))
    #print "Mask:", (":".join("{0:02x}".format(ord(c)) for c in self.mask))
    #print "Mask:", self.mask
    dsa = DSA.load_pub_key("keys/dsa_pub_xtr.pem")
    good = dsa.verify(digest, self.signature[0],self.signature[1])
    print "VerSign r:", (":".join("{0:02x}".format(ord(c)) for c in self.signature[0]))
    print "VerSign s:", (":".join("{0:02x}".format(ord(c)) for c in self.signature[1]))
    print 'VerSign: ', good
    return good
    
  def toRaw(self):
    raw = self.eid.toRaw() + struct.pack('>I', self.mask) + self.alpha
    raw += self.rloc_sp.toRaw() + self.xtr_id + self.ra_sp
    print "Mask:", (":".join("{0:02x}".format(ord(c)) for c in struct.pack('>I', self.mask)))
    return raw
    