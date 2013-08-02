""" 
    Authentication backends 
"""
from zope.interface import Interface, implements
from txeap.backends import auth
import ConfigParser

class InMemoryBackend(auth.AuthBackend):
    " A simple in memory backend. This should only ever be used for testing"
    implements(auth.IAuthBackend)

    def __init__(self, config):
        try:
            self.creds = dict(config.items('in_memory_backend'))
        except ConfigParser.NoSectionError:
            self.creds = {}

    def validate(self, username, password):
        pw = self.creds.get(username)
        if pw and pw==password:
            return True

        return False
