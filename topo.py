import os
from mininet.topo import Topo
from mininet.net import Mininet
# from mininet.node import CPULimitedHost
from mininet.link import TCLink, Intf
# from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, RemoteController
def startNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')
    info( '*** Adding remote Ryu controller\n' )
    c0 = net.addController(
        name = 'c0',
        controller = RemoteController,
        ip = '127.0.0.1',
        protocol = 'tcp',
        port = 6633
    )
    info('*** adding switch 1 and its respective hosts\n')
    s1=net.addSwitch('s1',cls=OVSKernelSwitch,protocols='OpenFlow13')
    h1=net.addHost('h1',cpu=1.0/20,mac="00:00:00:00:00:01",ip="10.0.0.1/24")      
    h2=net.addHost('h2',cpu=1.0/20,mac="00:00:00:00:00:02",ip="10.0.0.2/24")      
    h3=net.addHost('h3',cpu=1.0/20,mac="00:00:00:00:00:03",ip="10.0.0.3/24")      
    
    info('*** adding switch 2 and its respective hosts\n')

    s2=net.addSwitch('s2',cls=OVSKernelSwitch,protocols='OpenFlow13')
    h4=net.addHost('h4',cpu=1.0/20,mac="00:00:00:00:00:04",ip="10.0.0.4/24")      
    h5=net.addHost('h5',cpu=1.0/20,mac="00:00:00:00:00:05",ip="10.0.0.5/24")      
    h6=net.addHost('h6',cpu=1.0/20,mac="00:00:00:00:00:06",ip="10.0.0.6/24") 
    
    info('*** adding switch 3 and its respective hosts\n')

    s3=net.addSwitch('s3',cls=OVSKernelSwitch,protocols='OpenFlow13')
    h7=net.addHost('h7',cpu=1.0/20,mac="00:00:00:00:00:07",ip="10.0.0.7/24")      
    h8=net.addHost('h8',cpu=1.0/20,mac="00:00:00:00:00:08",ip="10.0.0.8/24")      
    h9=net.addHost('h9',cpu=1.0/20,mac="00:00:00:00:00:09",ip="10.0.0.9/24") 

    info('*** adding links\n')
    net.addLink(h1,s1)
    
    net.addLink(h2,s1)
    
    net.addLink(h3,s1)
    
    net.addLink(h4,s2)
    
    net.addLink(h5,s2)

    net.addLink(h6,s2)

    net.addLink(h7,s3)
    
    net.addLink(h8,s3)

    net.addLink(h9,s3)
    
    net.addLink(s1,s2)
    
    net.addLink(s2,s3)
    
    info('**** network staring\n')
    net.build()
    info('*** starting controller')
    for controller in net.controllers:
        controller.start

    info('*** starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])

    info('*** post config switches and hosts\n')
    CLI(net)
    net.stop()




if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
    