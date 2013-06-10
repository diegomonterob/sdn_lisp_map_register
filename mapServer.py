import sys
sys.path.append('./messages/')

from addresses import *
from MapRegister import *
from MapReply import *
from ErrorMessage import *
from Alpha import *
from Beta import *
from EID import *
import socket
import thread

UDP_IP = "0.0.0.0"
UDP_PORT = 4005
BUFFER_SIZE = 1024

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

#DEFINING EIDS
keys = {}
eid = EID("192.168.1.0",24,"10.0.0.1",b'diegodiegodiego1')
keys[(eid.eid.toStr() + '/' + str(eid.mask))] = [eid.key, b'qwertyuiop123456']

#************************************************
try:
  import cPickle as pickle
except:
  import pickle

  import sys

def verifySign(mapReg):
  return mapReg.verifySign()

def verifyAlpha(mapReg):
  
  if (mapReg.eid.toStr() + '/' + str(mapReg.mask)) in keys: 
      key = keys[(mapReg.eid.toStr() + '/' + str(mapReg.mask))][0]
      print 'EID: %s, SharedKey: %s' % (mapReg.eid, key)
  else:
    print '*** Key for EID: %s NOT DEFINED' % (mapReg.eid)
  alpharcvd = Alpha('0.0.0.0')
  alpharcvd.decrypt(mapReg.alpha,key)
  if (alpharcvd.eid == mapReg.eid and alpharcvd.mask == mapReg.mask and alpharcvd.xtr_id == mapReg.xtr_id):
    print '****ALPHA VALID'
    return [1, alpharcvd.ts, alpharcvd.xtr_id]
  else:
    return [-1, -1, -1]

def handleConnection(data, addr):
  o = pickle.loads(data)	#recieves mapRegister messages
  print repr(o) # prints array('i', [1, 3, 2])
  if (o.msg_type == MSG_MAP_REGISTER):
    print 'READ MapRegister: %s (mask: %s), RLOCsp: %s' % (o.eid, o.mask, o.rloc_sp)
    if verifySign(o):
      print '****Testing ALPHA'
      test,ts,xtr_id = verifyAlpha(o)
      
      #**TODO: VERIFICATION OF ROA
      #TEST IF THE XTR_ID BELONGS THE THE RLOC THAT BELONGS TO AN ASN
      
      if test == 1: #verifyAlpha(o)[0]:
	print 'EID Validated: ',o.eid
	ans = MapReply(o.eid, o.mask,ts,xtr_id)
	ans.generateSign()
      else:
	ans = ErrorMessage('alpha INCORRECT for EID %s' % o.eid.toStr())
    else:
      ans = ErrorMessage('signature INCORRECT for EID %s' % o.eid.toStr())
    
  else:
    ans = ErrorMessage('Message Unknown for MAP Server')
  
  sock.sendto(pickle.dumps(ans),addr)
  
if __name__ == '__main__':
  sock.bind((UDP_IP, UDP_PORT))
  while True:
    data, addr = sock.recvfrom(BUFFER_SIZE) # buffer size is 1024 bytes
    thread.start_new_thread(handleConnection, (data, addr))



      