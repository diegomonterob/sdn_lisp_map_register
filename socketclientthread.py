""" 
Simple socket client thread sample.

Eli Bendersky (eliben@gmail.com)
This code is in the public domain
"""
import socket
import struct
import threading
import Queue
try:
  import cPickle as pickle
except:
  import pickle

#MSG_SERVICE_REQUEST = 1
#MSG_MAP_REGISTER = 2
#MSG_MAP_REPLY = 3
#MSG_SERVICE_REPLY = 4
#MSG_OTP_ACK = 5
#MSG_ERROR = -1
import sys
sys.path.append('./messages/')
from ServiceRequest import *
from ServiceReply import *
from ServiceACK import *
from EID import *

class ClientCommand(object):
    """ A command to the client thread.
        Each command type has its associated data:
    
        SET_SERVER:          (host, port) tuple
        REQUEST_SERVICE   ServiceRequest Message
        RECEIVE:          None
        SERVICE_ACK_OTP   ServiceACK message
        CLOSE:            None
    """
    SET_SERVER, REQUEST_SERVICE, RECEIVE, SERVICE_ACK_OTP, CLOSE = range(5)
    
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


class SocketClientThread(threading.Thread):
  HOST = "127.0.0.1"
  PORT = 4004
  BUFF_SIZE=1024
  def __init__(self, cmd_q=Queue.Queue(), reply_q=Queue.Queue()):
    super(SocketClientThread, self).__init__()
    self.cmd_q = cmd_q
    self.reply_q = reply_q
    self.alive = threading.Event()
    self.alive.set()
    self.sock = None
       
    self.handlers = {
      #SET_SERVER, REQUEST_SERVICE, RECEIVE, SERVICE_ACK_OTP, CLOSE
      ClientCommand.SET_SERVER: self._handle_SET_SERVER,
      ClientCommand.REQUEST_SERVICE: self._handle_REQUEST_SERVICE,
      ClientCommand.RECEIVE: self._handle_RECEIVE,
      ClientCommand.SERVICE_ACK_OTP: self._handle_SERVICE_ACK_OTP,
      ClientCommand.CLOSE: self._handle_CLOSE,
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

  #SET_SERVER, REQUEST_SERVICE, RECEIVE, SERVICE_ACK_OTP, CLOSE
  def _handle_SET_SERVER(self, cmd):
    self.HOST = cmd.data[0]
    self.PORT = cmd.data[1]
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.reply_q.put(self._success_reply())

  def _handle_REQUEST_SERVICE(self, cmd):
    try:
      self.sock.sendto(pickle.dumps(cmd.data), (self.HOST,self.PORT))
      self.reply_q.put(self._success_reply(data='ServiceRequest sent!!'))
    except IOError as e:
      self.reply_q.put(self._error_reply(str(e)+'[Error ServiceRequest]'))
      
  def _handle_SERVICE_ACK_OTP(self, cmd):
    try:
      self.sock.sendto(pickle.dumps(cmd.data), (self.HOST,self.PORT))
      self.reply_q.put(self._success_reply(data='ACK_OTP sent!!'))
    except IOError as e:
      self.reply_q.put(self._error_reply(str(e)+'[Error ACK_OTP]')) 
    
  def _handle_CLOSE(self, cmd):
    self.sock.close()
    reply = ClientReply(ClientReply.SUCCESS,'Connection Closed!!')
    self.reply_q.put(reply)     
     
  def _handle_RECEIVE(self, cmd):
    try:
      received = self.sock.recv(self.BUFF_SIZE)
      self.reply_q.put(self._success_reply(received))
      
    except IOError as e:
      self.reply_q.put(self._error_reply(str(e)+'[Error Receive]'))

  def _error_reply(self, errstr):
    return ClientReply(ClientReply.ERROR, errstr)

  def _success_reply(self, data=None):
    return ClientReply(ClientReply.SUCCESS, data)


#------------------------------------------------------------------------------
if __name__ == "__main__":
  #DEFINING EIDS
  #eids = {}
  
  #keys[(answer.eid.toStr() + '/' + str(answer.mask))] = [answer.eid, answer.mask, answer.otp]
  
  eid = EID("192.168.1.0",24,"10.0.0.1",b'diegodiegodiego1')
  
  
  sct = SocketClientThread()
  sct.start()
  
  #SET_SERVER, REQUEST_SERVICE, RECEIVE, SERVICE_ACK_OTP, CLOSE
  
  
  sct.cmd_q.put(ClientCommand(ClientCommand.SET_SERVER, ('127.0.0.1', 4004)))
  reply = sct.reply_q.get(True)
  print(reply.type, reply.data)
  
  data = ServiceRequest(eid.eid,eid.mask,eid.ms,xtr_id=b'qwertyuiop123456', ts=b'09876543', key=eid.key)
      
  sct.cmd_q.put(ClientCommand(ClientCommand.REQUEST_SERVICE, data))
  reply = sct.reply_q.get(True)
  print(reply.type, reply.data)
  
  sct.cmd_q.put(ClientCommand(ClientCommand.RECEIVE, "receive"))
  reply = sct.reply_q.get(True)
  
  
  o = pickle.loads(reply.data)
  print(reply.type, repr(o))
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
    
    ack = ServiceACK(plainbeta.eid, plainbeta.mask, plainbeta.ts, plainbeta.ack, plainbeta.otp)
    
    sct.cmd_q.put(ClientCommand(ClientCommand.SERVICE_ACK_OTP, ack))
    reply = sct.reply_q.get(True)
    print(reply.type, reply.data)
    
  if (o.msg_type == MSG_ERROR):
    print '[MSG_ERROR] ',o.msg
  
  sct.cmd_q.put(ClientCommand(ClientCommand.CLOSE))
  reply = sct.reply_q.get(True)
  print(reply.type, reply.data)
  pass

