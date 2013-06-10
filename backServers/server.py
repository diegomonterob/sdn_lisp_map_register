import sys
sys.path.append('./messages/')

from ServiceRequest import *
from ServiceReply import *
from MapRegister import *
from MapReply import *
from ServiceACK import *
from ErrorMessage import *
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 4004

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

otp_to_ack = {}

try:
  import cPickle as pickle
except:
  import pickle

  import sys

def verifySign(mapRep):
  return mapRep.verifySign()  
  
def sendMapRegister(servReq): #servReg: ServiceRequest sent from client
  
  mapReg = MapRegister(servReq.eid,servReq.mask,servReq.alpha,'9.9.9.9')
  mapReg.generateSign()
  #mapReg.mask = 0
  sockms = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sockms.sendto( pickle.dumps(mapReg), (UDP_IP,4005))
  received = sockms.recv(1024)
  sockms.close()
  
  
  answer = pickle.loads(received) #MapReply answer
  print repr(answer)
  if (answer.msg_type == MSG_MAP_REPLY):
    if verifySign(answer):
      otp_to_ack[(answer.eid.toStr() + '/' + str(answer.mask))] = [answer.eid, answer.mask, answer.otp]   
      return (ServiceReply(answer.eid, answer.mask,answer.beta))# otp=0, ack=0,beta=0):
    else:
      return (ErrorMessage('MapReply signature INCORRECT%s' % o.eid.toStr()))
  else:
    return answer
  
  
if __name__ == '__main__':
  sock.bind((UDP_IP, UDP_PORT))
  while True:
    #ralpha=Alpha("0.0.0.0")
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    L = pickle.loads(data)
    print repr(L) # prints array('i', [1, 3, 2])
    ans = []
    for o in L:
      
      if (o.msg_type == MSG_SERVICE_REQUEST):
        print 'READ: ServiceRequest %s (%s), mask: %s' % (o.eid, o.ms, o.mask)
        ans.append(sendMapRegister(o))
        
      if (o.msg_type == MSG_OTP_ACK):
        print 'READ: ServiceACK %s, mask: %s' % (o.eid, o.mask)
        if (o.eid.toStr() + '/' + str(o.mask)) in otp_to_ack: 
          veid,vmask,votp = otp_to_ack[(o.eid.toStr() + '/' + str(o.mask))]
          gammaplain = Gamma(eid='0.0.0.0',otp=votp)
          gammaplain.decrypt(o.gamma)
          if gammaplain.eid == veid and gammaplain.mask ==vmask:
	    print 'Service ACK Validated EID %s/%s' % (veid, vmask)
	  else:
	    print 'Service ACK INCORRECT - EID: %s/%s, Rcvd_EID: %s/%s' % (veid, vmask, gammaplain.eid, gammaplain.mask)
        else:
	  print 'Service ACK not Requested EID ', o.eid
        #ans.append(sendMapRegister(o))
        #sendMapRegister(o)
        #print "Alpha:", (":".join("{0:02x}".format(ord(c)) for c in o.alpha))
 
 #THIS MESSAGES IS HANDLED BETWEEN THE XTR AND THE MS ON PORT 4005
      #if (o.msg_type == MSG_MAP_REPLY):
        #if verifySign(o):
          #ans.append(ServiceReply(o.eid, o.mask,o.beta))# otp=0, ack=0,beta=0):
        #else:
          #ans.append(ErrorMessage('MapReply signature INCORRECT%s' % o.eid.toStr()))
      
      #ralpha.decrypt(o.alpha)
      #ans.append(sedMapRegister(o))
    #sock.sendto(', '.join(ans), addr)
    sock.sendto(pickle.dumps(ans),addr)

    

  
#********************************************************************8
#from array import *
#import socket

#UDP_IP = "127.0.0.1"
#UDP_PORT = 4004

## SOCK_DGRAM is the socket type to use for UDP sockets
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#try:
  #import cPickle as pickle
#except:
  #import pickle

  #import sys

#class SimpleObject(object):

  #def __init__(self, name):
    #self.name = name
    #l = list(name)
    #l.reverse()
    #self.name_backwards = ''.join(l)
    #return

#if __name__ == '__main__':
  #sock.bind((UDP_IP, UDP_PORT))
  #while True:
    #data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    #L = pickle.loads(data)
    #print repr(L) # prints array('i', [1, 3, 2])
    #for o in L:
      #print 'READ: %s (%s)' % (o.eid., o.name_backwards)
    #sock.sendto("good", addr)
