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
import threading
import Queue

try:
  import cPickle as pickle
except:
  import pickle

#***************************************************************
class ClientCommand(object):
    """ A command to the client thread.
        Each command type has its associated data:
    
        SET_SERVER:       (host, port) tuple
        START             None
        CLOSE:            None
    """
    SET_SERVER, START, STOP = range(3)
    
    def __init__(self, type, data=None):
        self.type = type
        self.data = data


class ClientReply(object):
    """ A reply from the client thread.
        Each reply type has its associated data:
        
        ERROR:      The error string
        SUCCESS:    Depends on the command - for RECEIVE it's the received
                    data string, for others None.
    """
    ERROR, SUCCESS = range(2)
    
    def __init__(self, type, data=None):
        self.type = type
        self.data = data

#***************************************************************      


class Server(threading.Thread):
  UDP_IP = "127.0.0.1"
  UDP_PORT = 4004
  BUFFER_SIZE = 1024
  otp_to_ack = {}

  def __init__(self, cmd_q=Queue.Queue(), reply_q=Queue.Queue()):
    super(Server, self).__init__()
    self.cmd_q = cmd_q
    self.reply_q = reply_q
    self.alive = threading.Event()
    self.alive.set()
    self.sock = None

    self.handlers = {
      #SET_SERVER, START, STOP
      ClientCommand.SET_SERVER: self._handle_SET_SERVER,
      ClientCommand.START: self._handle_START,
      ClientCommand.STOP: self._handle_STOP,
      }
 
  def run(self):
    while self.alive.isSet():
      try:
        # Queue.get with timeout to allow checking self.alive
        cmd = self.cmd_q.get(True, 0.1)
        self.handlers[cmd.type](cmd)
      except Queue.Empty as e:
        continue
                
  def join(self, timeout=None):
    self.alive.clear()
    threading.Thread.join(self, timeout)
    
  #SET_SERVER, START, STOP
  def _handle_SET_SERVER(self, cmd):
    self.UDP_IP = cmd.data[0]
    self.UDP_PORT = cmd.data[1]
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.reply_q.put(self._success_reply())
    
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
      if self.verifySign(answer):
        self.otp_to_ack[(answer.eid.toStr() + '/' + str(answer.mask))] = [answer.eid, answer.mask, answer.otp]   
        return (ServiceReply(answer.eid, answer.mask,answer.beta))# otp=0, ack=0,beta=0):
      else:
        return (ErrorMessage('MapReply signature INCORRECT%s' % o.eid.toStr()))
    else:
      return answer

  def handleConnection(data,addr):
  #def _handle_START(self, cmd):
    #data = cmd[0]
    #addr = cmd[1]
    o = pickle.loads(data)
    print repr(o) # prints array('i', [1, 3, 2])

    if (o.msg_type == MSG_SERVICE_REQUEST):
      print 'READ: ServiceRequest %s (%s), mask: %s' % (o.eid, o.ms, o.mask)
      ans = (self.sendMapRegister(o))
      self.sock.sendto(pickle.dumps(ans),addr)
  
    if (o.msg_type == MSG_OTP_ACK):
      print 'READ: ServiceACK %s, mask: %s' % (o.eid, o.mask)
      if (o.eid.toStr() + '/' + str(o.mask)) in self.otp_to_ack: 
        veid,vmask,votp = self.otp_to_ack[(o.eid.toStr() + '/' + str(o.mask))]
        gammaplain = Gamma(eid='0.0.0.0',otp=votp)
        gammaplain.decrypt(o.gamma)
        if gammaplain.eid == veid and gammaplain.mask ==vmask:
          print 'Service ACK Validated EID %s/%s' % (veid, vmask)
        else:
          print 'Service ACK INCORRECT - EID: %s/%s, Rcvd_EID: %s/%s' % (veid, vmask, gammaplain.eid, gammaplain.mask)
      else:
        print 'Service ACK not Requested EID ', o.eid


  def _handle_START(self, cmd):
    self.sock.bind((self.UDP_IP, self.UDP_PORT))
    while True:
      #ralpha=Alpha("0.0.0.0")
      data, addr = self.sock.recvfrom(self.BUFFER_SIZE) # buffer size is 1024 bytes
      thread.start_new_thread(self.handleConnection, (data, addr))

  def _error_reply(self, errstr):
    return ClientReply(ClientReply.ERROR, errstr)

  def _success_reply(self, data=None):
    return ClientReply(ClientReply.SUCCESS, data)
    
  def _handle_STOP(self, cmd):
    self.sock.close()
    reply = ClientReply(ClientReply.SUCCESS,'Connection Closed!!')
    self.reply_q.put(reply)     

#------------------------------------------------------------------------------
if __name__ == "__main__":
 
  sserver = Server()
  sserver.start()
  #SET_SERVER, START, STOP
  
  sserver.cmd_q.put(ClientCommand(ClientCommand.SET_SERVER, ('127.0.0.1', 4004)))
  reply = sserver.reply_q.get(True)
  print(reply.type, reply.data)
  
  sserver.cmd_q.put(ClientCommand(ClientCommand.START))
  reply = sserver.reply_q.get(True)
  print(reply.type, reply.data)