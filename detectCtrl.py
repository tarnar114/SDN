from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import time
import numpy as np
from ryu.lib import hub
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from SVM import SVMmodel
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
class CustomController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CustomController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths={}
        self.monitor_thread = hub.spawn(self._monitor)
        self.time_interval=2
        self.state=0
        self.clf=SVMmodel()
        self.arp_ip_to_port={}
        self.blocked=False

    """
    monitor stuff
    """
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                parser=dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(self.time_interval)
    @set_ev_cls(ofp_event.EventOFPStateChange, [ MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _handle_state_change(self, ev):
        if ev.state == MAIN_DISPATCHER:
            if ev.datapath not in self.datapaths:
                print("[REGISTER SWITCH]:", ev.datapath.id)
                self.datapaths[ev.datapath.id] = ev.datapath
        elif ev.state == DEAD_DISPATCHER:
            if ev.datapath in self.datapaths:
                print("[DISCONNECT SWITCH]:", ev.datapath.id)
                del self.datapaths[ev.datapath.id]


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _handle_flow_stats_reply(self, ev):
        flows = sorted([flow for flow in ev.msg.body if flow.priority == 1], key=lambda flow:(flow.match["in_port"]))
        
        if len(flows)!=0:
            x=self.flow_stats(flows)                
            y=self.clf.predict(x)
            if (y[0]==1):
                self.state=1
                print("ddos is happening")
                # print("removeing flows")
                # self.remove_flows(ev.msg.datapath,0)
                                


    def flow_stats(self,flows):
        ip_src_set = set()
        ip_dst_set = set()
        port_src_set = set()
        port_dst_set = set()
        for flow in flows:
            ip_src_set.add(flow.match['ipv4_src'])
            ip_dst_set.add(flow.match['ipv4_dst'])
            if flow.match['ip_proto'] == 1: # ICMP
                pass
            elif flow.match['ip_proto'] == 17:  # UDP 
                port_src_set.add(flow.match['udp_src'])
                port_dst_set.add(flow.match['udp_dst'])
            elif flow.match['ip_proto'] == 6: # TCP
                port_src_set.add(flow.match['tcp_src'])
                port_dst_set.add(flow.match['tcp_dst'])
        SSIP = len(ip_src_set) / self.time_interval
        SSP = len(port_src_set) / self.time_interval

        packet_set=list()
        byte_set=list()
        for flow in flows:
            packet_set.append(flow.packet_count)
            byte_set.append(flow.byte_count)
        SDFP=np.std(packet_set)
        SDFB=np.std(byte_set)

        SFE = len(flows) / self.time_interval
        # print ("SSIP:{},SSP:{},SDFP:{},SDFB:{},SFE:{}".format(SSIP,SSP,SDFP,SDFB,SFE))
        return [SSIP, SSP, SDFP, SDFB, SFE]

    """
    
    Switch stuff
    
    """
    def remove_flows(self, datapath, table_id):
            """Removing all flow entries."""
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            empty_match = parser.OFPMatch()
            instructions = []
            flow_mod = self.remove_table_flows(datapath, table_id,
                                            empty_match, instructions)
            print("deleting all flow entries in table ", table_id)
            datapath.send_msg(flow_mod)
    

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
    # From simple_switch_13
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def block_port(self,dp,port):
        ofproto=dp.ofproto
        parser=dp.ofproto_parser
        match=parser.OFPMatch(in_port=port)
        actions=[]
        flow_serial_no=1
        # self.blocked=True
        print("blocked")
        self.add_flow(dp,1,match,actions,flow_serial_no,hardtime=120)
    # add a new flow(rule) to switch.
    #   priority : the packet will match the highest priority to match, then follw the action to deal with packet.
    #   match    : set the match condition, ex: 1 = msg.match['in_port']
    #                                           packet from port 1 will be match.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None,hardtime=0,idletime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,hard_timeout=hardtime,idle_timeout=idletime)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Event: Handle packet sent from switch to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dl_dst = eth.dst
        dl_src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid,{})
        self.arp_ip_to_port[dpid].setdefault(in_port,[])
        # self.logger.info("packet in %s %s %s %s", dpid, dl_src, dl_dst, in_port)
        #     self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, 
        #         ip_src, ip_dst)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][dl_src] = in_port


        if dl_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dl_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            #self.logger.info("Received ARP Packet %s %s %s ", dpid, src, dst)
            a = pkt.get_protocol(arp.arp)
            #print "arp packet ", a
            if a.opcode == arp.ARP_REQUEST or a.opcode == arp.ARP_REPLY:
                if not a.src_ip in self.arp_ip_to_port[dpid][in_port]:
                    self.arp_ip_to_port[dpid][in_port].append(a.src_ip)
                    #print "arp_ip_to_port " ,self.arp_ip_to_port

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                
                if self.state ==1 :
                    if not (srcip in self.arp_ip_to_port[dpid][in_port]):
                        self.block_port(datapath, in_port)
                        #print ip
                        return



                # Default Match of Ryu: simple_switch_13 module
                # match = parser.OFPMatch(in_port=in_port, eth_dst=dl_dst, eth_src=dl_src)
                
                # If ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    icmp_info = pkt.get_protocol(icmp.icmp)
                    print(icmp_info.type)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,
                                            ipv4_dst=dstip,
                                            eth_src=dl_src,
                                            eth_dst=dl_dst,
                                            in_port=in_port,
                                            ip_proto=protocol,
                                            )
    
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,
                                            ipv4_dst=dstip,
                                            eth_dst=dl_dst,
                                            eth_src=dl_src,
                                            ip_proto=protocol,
                                            in_port=in_port,
                                            udp_src=u.src_port,
                                            udp_dst=u.dst_port,
                                            )          

                # if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    tcp_src = t.src_port
                    tcp_dst = t.dst_port
                    # Custom match
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,
                                            ipv4_dst=dstip,
                                            eth_dst=dl_dst,
                                            eth_src=dl_src,
                                            ip_proto=protocol,
                                            in_port=in_port,
                                            tcp_src=tcp_src,
                                            tcp_dst=tcp_dst,
                                            )

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
                    
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        