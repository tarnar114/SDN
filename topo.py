import os
from mininet.topo import Topo
from mininet.net import Mininet
# from mininet.node import CPULimitedHost
from mininet.link import TCLink, Intf
# from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController

class NormalNetWork(Topo):
    def build(self):
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")
        s1 =self.addSwitch("s1", cls=OVSKernelSwitch, protocol="OpenFlow13")
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)

def attacker_host(host):
    pass
def victim_server(server):
    pass
def normal_host(host):
    pass

if __name__ == "__main__":
    # NetWork Setting
    c0 = RemoteController("c0", ip="127.0.0.1", port=6653)
    net = Mininet(topo=NormalNetWork(), controller=c0)
    ## NetWork Start
    net.start()
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h4 = net.get("h4")
    CLI(net)
    net.stop()