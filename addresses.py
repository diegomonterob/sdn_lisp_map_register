# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
Classes for addresses of various types.
"""
import struct
import socket

class IPAddr (object):
  """
  Represents an IPv4 address.
  """
  def __init__ (self, addr, networkOrder = False):
    """ Can be initialized with several formats.
        If addr is an int/long, then it is assumed to be in host byte order
        unless networkOrder = True
        Stored in network byte order as a signed int
    """

    # Always stores as a signed network-order int
    if isinstance(addr, basestring) or isinstance(addr, bytes):
      if len(addr) != 4:
        # dotted quad
        self._value = struct.unpack('i', socket.inet_aton(addr))[0]
        #print "address %i" % (self._value)
        #print "address:", (":".join("{0:x}".format(ord(c)) for c in self._value))
      else:
        self._value = struct.unpack('i', addr)[0]
        
    elif isinstance(addr, IPAddr):
      self._value = addr._value
    elif isinstance(addr, int) or isinstance(addr, long):
      addr = addr & 0xffFFffFF # unsigned long
      self._value = struct.unpack("!i",
          struct.pack(('!' if networkOrder else '') + "I", addr))[0]
    else:
      raise RuntimeError("Unexpected IP address format")

  def toSignedN (self):
    """ A shortcut """
    return self.toSigned(networkOrder = True)

  def toUnsignedN (self):
    """ A shortcut """
    return self.toUnsigned(networkOrder = True)

  def toSigned (self, networkOrder = False):
    """ Return the address as a signed int """
    if networkOrder:
      return self._value
    v = socket.htonl(self._value & 0xffFFffFF)
    return struct.unpack("i", struct.pack("I", v))[0]

  def toRaw (self):
    """
    Returns the address as a four-character byte string.
    """
    return struct.pack("i", self._value)

  def toUnsigned (self, networkOrder = False):
    """
    Returns the address as an integer in either network or host (the
    default) byte order.
    """
    if not networkOrder:
      return socket.htonl(self._value & 0xffFFffFF)
    return self._value & 0xffFFffFF

  def toStr (self):
    """ Return dotted quad representation """
    return socket.inet_ntoa(self.toRaw())

  def in_network (self, *args, **kw):
    return self.inNetwork(*args, **kw)

  def inNetwork (self, network, netmask = None):
    """
    Returns True if this network is in the specified network.
    network is a dotted quad (with or without a CIDR or normal style
    netmask, which can also be specified separately via the netmask
    parameter), or it can be a tuple of (address,network-bits) like that
    returned by parse_cidr().
    """
    if type(network) is not tuple:
      if netmask is not None:
        network = str(network)
        network += "/" + str(netmask)
      n,b = parse_cidr(network)
    else:
      n,b = network
      if type(n) is not IPAddr:
        n = IPAddr(n)

    return (self.toUnsigned() & ~((1 << (32-b))-1)) == n.toUnsigned()

  def __str__ (self):
    return self.toStr()

  def __cmp__ (self, other):
    if other is None: return 1
    try:
      if not isinstance(other, IPAddr):
        other = IPAddr(other)
      return cmp(self.toUnsigned(), other.toUnsigned())
    except:
      return -other.__cmp__(self)

  def __hash__ (self):
    return self._value.__hash__()

  def __repr__ (self):
    return self.__class__.__name__ + "('" + self.toStr() + "')"

  def __len__ (self):
    return 4

  def __setattr__ (self, a, v):
    if hasattr(self, '_value'):
      raise TypeError("This object is immutable")
    object.__setattr__(self, a, v)


def netmask_to_cidr (dq):
  """
  Takes a netmask as either an IPAddr or a string, and returns the number
  of network bits.  e.g., 255.255.255.0 -> 24
  Raise exception if subnet mask is not CIDR-compatible.
  """
  if isinstance(dq, basestring):
    dq = IPAddr(dq)
  v = dq.toUnsigned(networkOrder=False)
  c = 0
  while v & 0x80000000:
    c += 1
    v <<= 1
  v = v & 0xffFFffFF
  if v != 0:
    raise RuntimeError("Netmask %s is not CIDR-compatible" % (dq,))
  return c


def cidr_to_netmask (bits):
  """
  Takes a number of network bits, and returns the corresponding netmask
  as an IPAddr.  e.g., 24 -> 255.255.255.0
  """
  v = (1 << bits) - 1
  v = v << (32-bits)
  return IPAddr(v, networkOrder = False)


def parse_cidr (addr, infer=True, allow_host=False):
  """
  Takes a CIDR address or plain dotted-quad, and returns a tuple of address
  and count-of-network-bits.
  Can infer the network bits based on network classes if infer=True.
  Can also take a string in the form 'address/netmask', as long as the
  netmask is representable in CIDR.

  FIXME: This function is badly named.
  """
  def check (r0, r1):
    a = r0.toUnsigned()
    b = r1
    if (not allow_host) and (a & ((1<<b)-1)):
      raise RuntimeError("Host part of CIDR address is not zero (%s)"
                         % (addr,))
    return (r0,32-r1)
  addr = addr.split('/', 2)
  if len(addr) == 1:
    if infer is False:
      return check(IPAddr(addr[0]), 0)
    addr = IPAddr(addr[0])
    b = 32-infer_netmask(addr)
    m = (1<<b)-1
    if (addr.toUnsigned() & m) == 0:
      # All bits in wildcarded part are 0, so we'll use the wildcard
      return check(addr, b)
    else:
      # Some bits in the wildcarded part were set, so we'll assume it was a host
      return check(addr, 0)
  try:
    wild = 32-int(addr[1])
  except:
    # Maybe they passed a netmask
    m = IPAddr(addr[1]).toUnsigned()
    b = 0
    while m & (1<<31):
      b += 1
      m <<= 1
    if m & 0x7fffffff != 0:
      raise RuntimeError("Netmask " + str(addr[1]) + " is not CIDR-compatible")
    wild = 32-b
    assert wild >= 0 and wild <= 32
    return check(IPAddr(addr[0]), wild)
  assert wild >= 0 and wild <= 32
  return check(IPAddr(addr[0]), wild)


def infer_netmask (addr):
  """
  Uses network classes to guess the number of network bits
  """
  addr = addr.toUnsigned()
  if addr == 0:
    # Special case -- default network
    return 32-32 # all bits wildcarded
  if (addr & (1 << 31)) == 0:
    # Class A
    return 32-24
  if (addr & (3 << 30)) == 2 << 30:
    # Class B
    return 32-16
  if (addr & (7 << 29)) == 6 << 29:
    # Class C
    return 32-8
  if (addr & (15 << 28)) == 14 << 28:
    # Class D (Multicast)
    return 32-0 # exact match
  # Must be a Class E (Experimental)
    return 32-0


IP_ANY = IPAddr("0.0.0.0")
IP_BROADCAST = IPAddr("255.255.255.255")

MSG_SERVICE_REQUEST = 1
MSG_MAP_REGISTER = 2
MSG_MAP_REPLY = 3
MSG_SERVICE_REPLY = 4
MSG_OTP_ACK = 5
MSG_ERROR = -1

if __name__ == '__main__':
  # A couple sanity checks
  #TODO: move to tests
  import code
  a = IPAddr('255.0.0.1')
  print (a.toStr)
  
  #print([parse_cidr(x)[1]==24 for x in
    #["192.168.101.0","192.168.102.0/24","1.1.168.103/255.255.255.0"]])
  
  #for v in [('255.0.0.1',True), (0xff000001, True), (0x010000ff, False)]:
    #print("== " + str(v) + " =======================")
    #a = IPAddr(v[0],v[1])
    #print(a._value,-16777215)
    ##print(hex(a._value),'ff000001')
    #print(str(a),'255.0.0.1')
    #print(hex(a.toUnsigned()),'010000ff')
    #print(hex(a.toUnsigned(networkOrder=True)),'ff000001')
    #print(a.toSigned(),16777471)
    #print(a.toSigned(networkOrder=True),-16777215)
    #print("----")
    #print([parse_cidr(x)[1]==24 for x in
           #["192.168.101.0","192.168.102.0/24","1.1.168.103/255.255.255.0"]])
  #code.interact(local=locals())

