import sys
sys.path.append('./messages/')

from addresses import *
from MapRegister import *
from MapReply import *
from ErrorMessage import *
from Alpha import *
from Beta import *
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 4005

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
  import cPickle as pickle
except:
  import pickle

  import sys

def verifySign(mapReg):
  return mapReg.verifySign()

def verifyAlpha(mapReg):
  alpharcvd = Alpha('0.0.0.0')
  alpharcvd.decrypt(mapReg.alpha)
  if (alpharcvd.eid == mapReg.eid and alpharcvd.mask == mapReg.mask and alpharcvd.xtr_id == mapReg.xtr_id):
    return [1, alpharcvd.ts]
  else:
    return [-1, -1]
  
if __name__ == '__main__':
  sock.bind((UDP_IP, UDP_PORT))
  while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    o = pickle.loads(data)	#recieves mapRegister messages
    print repr(o) # prints array('i', [1, 3, 2])
    #for o in L:
    print 'READ MapRegister: %s (mask: %s), RLOCsp: %s' % (o.eid, o.mask, o.rloc_sp)
    if verifySign(o):
      #ans = ErrorMessage('signature CORRECT for eid %s' % o.eid.toStr())
      test,ts = verifyAlpha(o)
      if test: #verifyAlpha(o)[0]:
        print 'EID Validated: ',o.eid
        ans = MapReply(o.eid, o.mask,ts)# otp=0, ack=0,beta=0):
        ans.generateSign()
      else:
	ans = ErrorMessage('alpha INCORRECT for EID %s' % o.eid.toStr())
    else:
      ans = ErrorMessage('signature INCORRECT for EID %s' % o.eid.toStr())
    sock.sendto(pickle.dumps(ans),addr)


      