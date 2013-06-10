from addresses import *
from LISPMessage import *

class ErrorMessage(LISPMessage):
  def __init__ (self,msg):
    self.msg_type = MSG_ERROR
    self.msg = msg
    return
    