from addresses import *
from LISPMessage import *
from M2Crypto import EVP, DSA, util
import struct 


class ServiceReply(LISPMessage):
  def __init__ (self, eid, mask,beta):
    self.msg_type = MSG_SERVICE_REPLY
    self.eid = IPAddr(eid)		#EID to register
    #self.mask = struct.pack('>I', mask)#EID mask
    self.mask = mask
    self.beta = beta
    return
   
  def toRaw(self):
    raw = self.eid.toRaw() + struct.pack('>I', self.mask) + self.beta
    return raw
    