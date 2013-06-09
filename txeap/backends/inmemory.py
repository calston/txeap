""" 
    Authentication backends 
"""
from zope.interface import Interface, implements
from txeap.backends import auth

class InMemoryBackend(auth.AuthBackend):
    " A simple in memory backend. This should only ever be used for testing"
    implements(auth.IAuthBackend)

    def __init__(self, config):
        self.creds = dict(config.items('in_memory_backend'))

    def validate(self, username, password):
        pw = self.creds.get(username)
        if pw and pw==password:
            return True

        return False
