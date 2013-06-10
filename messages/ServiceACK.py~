from addresses import *
from LISPMessage import *
from Beta import *
from Gamma import *
from M2Crypto import EVP, DSA, util
import struct 


class ServiceACK(LISPMessage):
  def __init__ (self, eid, mask, ts, ack, otp):
    self.msg_type = MSG_OTP_ACK
    self.eid = IPAddr(eid)		#EID to register
    #self.mask = struct.pack('>I', mask)#EID mask
    self.mask = mask
    gammaplain = Gamma(eid, mask, ts, ack, otp)
    self.gamma = gammaplain.encrypt()
    return
  
  def generateSign(self):
    message = self.toRaw()
    md = EVP.MessageDigest('sha1')
    md.update(message)        
    digest = md.final()
    dsa = DSA.load_key("keys/dsa_priv_ms.pem")
    self.signature = dsa.sign(digest)
    return
  
  def verifySign(self):
    message = self.toRaw()
    md = EVP.MessageDigest('sha1')
    md.update(message)        
    digest = md.final()
    dsa = DSA.load_pub_key("keys/dsa_pub_ms.pem")
    good = dsa.verify(digest, self.signature[0],self.signature[1])
    print "*** Verifying MapReply sign ", good
    return good
    
  def toRaw(self):
    raw = self.eid.toRaw() + struct.pack('>I', self.mask) + self.otp + self.ack + self.beta
    return raw
    