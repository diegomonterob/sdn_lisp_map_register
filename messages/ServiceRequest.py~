from addresses import *
from LISPMessage import *
from Alpha import *

class ServiceRequest(LISPMessage):
  def __init__ (self, eid, mask, ms ,xtr_id = b'1234567890123456',ts = b'12345678', key = b'Sixteen byte keySixteen byte key'):
    self.msg_type = MSG_SERVICE_REQUEST
    self.eid = IPAddr(eid)
    self.mask = mask
    self.ms = IPAddr(ms)
    alphaplain = Alpha(eid,mask,xtr_id,ts)
    self.alpha=alphaplain.encrypt(key)
    return
    
  def set_xtr_id(xtr_id):
    self.xtr_id = xtr_id
    return
  
  def set_ts(ts):
    self.ts = ts
    return
        
  def createAlpha(self,passwd, xtr_id = b'1234567890123456', ts = b'12345678'):
    #if len(passwd)%16 != 0:
      #return -1
    alphaplain = Alpha (self.eid, self.mask, xtr_id, ts)
    self.alpha = alphaplain.encrypt(passwd)
    return
    