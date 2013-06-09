""" 
    Authentication backends 
"""

from OpenSSL import SSL
from twisted.internet import reactor, ssl, defer
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from zope.interface import Interface, implements

from txeap.backends import auth

import base64


class ClientTLSContext(ssl.ClientContextFactory):
    isClient = 1
    def getContext(self):
        return SSL.Context(SSL.TLSv1_METHOD)

class SMTPTLSClient(LineReceiver):
    # Terrible and crufty SMTP client which only does authentication
    def __init__(self, *a, **kw):
        self.script = [
            ('220', self.sendEHLO),
            ('250', self.sendSTARTTLS),
            ('220', self.sendEHLO),
            ('250', self.sendAUTH),
            ('235', self.authComplete),
            (None, self.quit)
        ]

    def connectionMade(self):
        self.point = 0

    def quit(self, cd, dt):
        self.sendLine('QUIT')

    def sendEHLO(self, cd, dt):
        self.sendLine('EHLO me')
        self.point+=1

    def sendSTARTTLS(self, cd, dt):
        self.sendLine('STARTTLS')
        self.point+=1

    def sendAUTH(self, cd, dt):
        auth = base64.b64encode('%s\x00%s\x00%s' % (
            self.factory.user,
            self.factory.user,
            self.factory.password
        ))
        self.sendLine('AUTH PLAIN '+auth)
        self.point+=1

    def authComplete(self, cd, dt):
        self.factory.auth=True
        self.sendLine('QUIT')

    def lineReceived(self, line):
        cd = line[:3]
        dt = line[4:]

        code, send = self.script[self.point]

        if cd[0]!= '2':
            # Any error
            self.sendLine('QUIT')
      
        if (not code) or (cd == code):
            if (self.point==2):
                # Start TLS
                ctx = ClientTLSContext()
                self.transport.startTLS(ctx, self.factory)
     
            send(cd, dt)
            
class SMTPTLSClientFactory(ClientFactory):
    protocol = SMTPTLSClient

    def __init__(self, user, password, deferred):
        self.result = deferred
        self.user = user
        self.password = password
        self.auth = False

    def clientConnectionFailed(self, connector, reason):
        self.result.errback(err.value)

    def clientConnectionLost(self, connector, reason):
        if self.auth:
            self.result.callback(True)
        else:
            self.result.errback(reason.value)

def authSMTPUser(user, password):
    d = defer.Deferred()
    factory = SMTPTLSClientFactory(user, password, d)

    reactor.connectTCP('smtp.gmail.com', 587, factory)

    return d

class GoogleBackend(auth.AuthBackend):
    "A Google auth backend"
    implements(auth.IAuthBackend)
        
    def __init__(self, config):
        try:
            self.config = dict(config.items('google_backend'))
        except:
            # Backend not configured
            self.config = {}

        self.suffix = self.config.get('suffix')

    @defer.inlineCallbacks
    def validate(self, username, password):
        if not self.config:
            defer.returnValue(False)

        auth_user = username+"@"+self.suffix

        auth = yield authSMTPUser(auth_user, password)

        defer.returnValue(auth==True)
