from addresses import *

class EID(object):
  
  def __init__(self, eid, mask, ms="0.0.0.0", key=""):
    self.eid = IPAddr(eid)
    self.mask = mask
    self.ms = IPAddr(ms)
    self.key = key
    return
    
  def setKey(key):
    self.key = key
    return