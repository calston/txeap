""" 
    Authentication backends 
"""
from txeap.backends import inmemory, googleauth

backends = [
        inmemory.InMemoryBackend,
        googleauth.GoogleBackend
    ]
