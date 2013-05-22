from txeap import server

def createService(config):
    return server.RadiusServer(config)
