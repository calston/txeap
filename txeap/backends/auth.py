""" 
    Authentication backends 
"""
from zope.interface import Interface, implements

class AuthBackend(object):
    pass

class IAuthBackend(Interface):
    def validate(self, username, password):
        pass
