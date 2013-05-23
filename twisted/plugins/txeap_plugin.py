from zope.interface import implements

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet

import ConfigParser

import txeap 


class Options(usage.Options):
    optParameters = [
        ["port", "p", 1812, "The port to listen on."],
        ["config", "c", "/etc/txeap.conf", "Configuration file"]
    ]


class ServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "txeap"
    description = "EAP radius authentication server"
    options = Options

    def makeService(self, options):
        config = ConfigParser.SafeConfigParser()
        config.read(options['config'])

        return internet.UDPServer(
            int(options['port']), 
            txeap.createService(config)
        )


serviceMaker = ServiceMaker()
