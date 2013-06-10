import sys
sys.path.append('./messages/')

from ServiceRequest import *
from ServiceReply import *
from MapRegister import *
from MapReply import *
from ServiceACK import *
from ErrorMessage import *
import socket
import thread

UDP_IP = "127.0.0.1"
UDP_PORT = 4004
BUFFER_SIZE = 1024

# SOCK_DGRAM is the socket type to use for UDP sockets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

otp_to_ack = {}

try:
  import cPickle as pickle
except:
  import pickle


def verifySign(mapRep):
  return mapRep.verifySign()  
  
def sendMapRegister(servReq): #servReg: ServiceRequest sent from client
  
  """TODO: DEFINE ROA AND CREATE THE MAP REGISTER MESSAGE USING THE RLOC AND XTR_ID
  CONTAINDED IN IT
  Here, I am defining the xtr_id and the RLOC by hand. The xtr_id must be the sames as
  the one used by the client to achieve the Registration
  """
  
  mapReg = MapRegister(servReq.eid,servReq.mask,servReq.alpha,'9.9.9.9', xtr_id=b'qwertyuiop123456',ra_sp=b'authorized')
  
  mapReg.generateSign()
  
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

def handleConnection(data,addr):
  o = pickle.loads(data)
  print repr(o) # prints array('i', [1, 3, 2])

  if (o.msg_type == MSG_SERVICE_REQUEST):
    print 'READ: ServiceRequest %s (%s), mask: %s' % (o.eid, o.ms, o.mask)
    ans = (sendMapRegister(o))
    sock.sendto(pickle.dumps(ans),addr)
        
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
  else:
    print ('Message Unknown for MAP Server')
    
  
if __name__ == '__main__':
  sock.bind((UDP_IP, UDP_PORT))
  while True:
    #ralpha=Alpha("0.0.0.0")
    data, addr = sock.recvfrom(BUFFER_SIZE) # buffer size is 1024 bytes
    thread.start_new_thread(handleConnection, (data, addr))


    

