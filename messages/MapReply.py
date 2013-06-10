from addresses import *
from LISPMessage import *
from Beta import *

from M2Crypto import EVP, DSA, util
import struct 


class MapReply(LISPMessage):
  def __init__ (self, eid, mask, ts, xtr_id, ack = b'ackTOxTROKackTOx', key = b'Sixteen byte keySixteen byte key'):
    self.msg_type = MSG_MAP_REPLY
    self.eid = IPAddr(eid)		#EID to register
    #self.mask = struct.pack('>I', mask)#EID mask
    self.mask = mask
    
    betaplain = Beta(eid,mask,xtr_id,ts=ts, ack=ack)#,xtr_id=0,ts=0,otp='',ack=0)
    betaplain.ack = ack
    betaplain.ts = ts
    self.beta = betaplain.encrypt(key)
    self.otp = betaplain.otp
    self.ack = betaplain.ack #ack #betaplain.ack: ACK FOR THE XTR
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