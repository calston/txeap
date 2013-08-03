from StringIO import StringIO
from twisted.internet.interfaces import ITransport
from zope.interface import implements

class StringTransport:
    implements(ITransport)

    disconnecting = False

    producer = None
    streaming = None

    hostAddr = None
    peerAddr = None

    producerState = 'producing'

    def __init__(self, hostAddress=None, peerAddress=None):
        self.clear()
        if hostAddress is not None:
            self.hostAddr = hostAddress
        if peerAddress is not None:
            self.peerAddr = peerAddress
        self.connected = True

    def clear(self):
        """
        Discard all data written to this transport so far.

        This is not a transport method.  It is intended for tests.  Do not use
        it in implementation code.
        """
        self.io = StringIO()

    def value(self):
        """
        Retrieve all data which has been buffered by this transport.

        This is not a transport method.  It is intended for tests.  Do not use
        it in implementation code.

        @return: A C{str} giving all data written to this transport since the
            last call to L{clear}.
        @rtype: C{str}
        """
        return self.io.getvalue()

    # ITransport
    def write(self, data):
        if isinstance(data, unicode): # no, really, I mean it
            raise TypeError("Data must not be unicode")
        print 'IOTransport', repr(data)
        self.io.write(data)

    def writeSequence(self, data):
        self.io.write(''.join(data))

    def loseConnection(self):
        """
        Close the connection. Does nothing besides toggle the C{disconnecting}
        instance variable to C{True}.
        """
        print "Transport lost connection"
        self.disconnecting = True

    def getPeer(self):
        if self.peerAddr is None:
            return address.IPv4Address('TCP', '192.168.1.1', 54321)
        return self.peerAddr

    def getHost(self):
        if self.hostAddr is None:
            return address.IPv4Address('TCP', '10.0.0.1', 12345)
        return self.hostAddr

