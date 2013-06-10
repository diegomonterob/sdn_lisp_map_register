import sys
sys.path.append('./messages/')
import socket
#from addresses import *
from ServiceRequest import *
from ServiceReply import *
from ServiceACK import *

from Beta import *
from Gamma import *

from ErrorMessage import *

#MSG_SERVICE_REQUEST = 1
#MSG_MAP_REGISTER = 2
#MSG_MAP_REPLY = 3
#MSG_SERVICE_REPLY = 4
#MSG_OTP_ACK = 5
#MSG_ERROR = -1

HOST = "127.0.0.1"
PORT = 4004

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
  import cPickle as pickle
except:
  import pickle

if __name__ == '__main__':
  data = []
  data.append(ServiceRequest("192.168.1.0",24,"10.0.0.1"))
  data.append(ServiceRequest("192.168.2.0",24,"10.0.0.1"))

  sock.sendto( pickle.dumps(data), (HOST,PORT))
  received = sock.recv(1024)
  sock.close()

  for o in data:
    if (o.msg_type == MSG_SERVICE_REQUEST):
      print 'SENT: ServiceRequest %s (%s), mask: %s' % (o.eid, o.ms, o.mask)
    if (o.msg_type == MSG_MAP_REGISTER):
      print 'SENT: MapRegister ',o.rloc_sp.toStr()
    print "EID:", (":".join("{0:02x}".format(ord(c)) for c in o.eid.toRaw()))
 
 
  L = pickle.loads(received)
  print repr(L) # prints array('i', [1, 3, 2])
  for o in L:
    if (o.msg_type == MSG_SERVICE_REPLY):
      print '[MSG_SERVICE_REPLY]: ServiceReply EID %s, mask: %s' % (o.eid, o.mask)
      print "Beta:", (":".join("{0:02x}".format(ord(c)) for c in o.beta))
      plainbeta = Beta('0.0.0.0')
      plainbeta.decrypt(o.beta)
      print '[Beta] eid: ', plainbeta.eid
      print '[Beta] mask: ', plainbeta.mask
      print '[Beta] xtr_id: ', plainbeta.xtr_id
      print '[Beta] ts: ', plainbeta.ts
      print '[Beta] otp: ', plainbeta.otp
      print '[Beta] ack: ', plainbeta.ack
      ack = []
      ack.append (ServiceACK(plainbeta.eid, plainbeta.mask, plainbeta.ts, plainbeta.ack, plainbeta.otp))
      sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      sock.sendto( pickle.dumps(ack), (HOST,PORT))
      received = sock.recv(1024)
      sock.close()
      
    if (o.msg_type == MSG_ERROR):
      print '[MSG_ERROR] ',o.msg
    
#***************************************************************************
#import socket

#HOST = "127.0.0.1"
#PORT = 4004

## SOCK_DGRAM is the socket type to use for UDP sockets
#sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#try:
  #import cPickle as pickle
#except:
  #import pickle

#import sys
#from array import *

#class SimpleObject(object):

  #def __init__(self, name):
    #self.name = name
    #l = list(name)
    #l.reverse()
    #self.name_backwards = ''.join(l)
    #return

#if __name__ == '__main__':
  #data = []
  #data.append(SimpleObject('pickle'))
  #data.append(SimpleObject('cPickle'))
  #data.append(SimpleObject('last'))
  
  #sock.sendto( pickle.dumps(data), (HOST,PORT))
  #received = sock.recv(1024)
  #sock.close()

  #for o in data:
    #print 'SENT: %s (%s)' % (o.name, o.name_backwards)
  
  #print "Received: {}".format(received)