from addresses import *

from M2Crypto import EVP, DSA, util
import struct 


class LISPMessage(object):
  msg_type = 0
  def __init__ (self, msg_type=MSG_SERVICE_REQUEST):
    self.msg_type = msg_type
    return