from twisted.internet import reactor, defer
from twisted.trial import unittest
from twisted.python import log

from txeap import packet
from txeap.backends import inmemory, googleauth

TEST_CREDS = ('test', 'test')


class FakeConfig(object):
    def items(self, *a):
        return {'suffix': 'gmail.com'}

class Tests(unittest.TestCase):

    @defer.inlineCallbacks
    def test_googleauth(self):
        backend = googleauth.GoogleBackend(FakeConfig())
        r = yield backend.validate(*TEST_CREDS)
        
