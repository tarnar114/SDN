from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER,DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import math,csv,os
import numpy as np
from ryu.lib import hub

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class CustomController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CustomController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths={}
        self.monitor_thread = hub.spawn(self._monitor)
        self.time_interval=2
        self.label=0
        self.collect_count=0
        self.max_data_count=300
        if os.path.isfile("./data/data.csv"):
            with  open("./data/data.csv", "w", newline="") as f:
                f_writer = csv.writer(f)
                f_writer.writerow(["SSIP", "SSP", "SDFP", "SDFB", "SFE","RFIP", "label"])
    """
    monitor stuff
    """
    def _monitor(self):
        while True:
            if self.collect_count>self.max_data_count:
                print('collection done')
                return
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
        if len(flows) != 0 :
            # print("[Flow Stats]")
            # self.log_flows_match(flows)
            self.flow_stats_collect(flows)

    def flow_stats_collect(self, flows):
        #collection count just so csv doesnt get overwhelmed
        self.collect_count+=1
        #sets for necessary flow characteristics: src ip, destination ip, port src, port destination
        ip_src_set=set()
        ip_dst_set=set()
        port_src_set=set()
        port_dst_set=set()
        for flow in flows:
            #add corresponding characteristics to sets
            ip_src_set.add(flow.match['ipv4_src'])
            ip_dst_set.add(flow.match['ipv4_dst'])
            #add corresponding port src and port dest based on appropriate ip proto number
            if flow.match['ip_proto'] == 1: # ICMP
                pass
            elif flow.match['ip_proto'] == 17:  # UDP 
                port_src_set.add(flow.match['udp_src'])
                port_dst_set.add(flow.match['udp_dst'])
            elif flow.match['ip_proto'] == 6: # TCP
                port_src_set.add(flow.match['tcp_src'])
                port_dst_set.add(flow.match['tcp_dst'])
            elif flow.match['ip_proto'] == 132:
                port_src_set.add(flow.match['sctp_src'])
                port_dst_set.add(flow.match('sctp_dst'))
        #spped of source ip and source port
        SSIP = len(ip_src_set) / self.time_interval
        SSP=len(port_src_set)/ self.time_interval
        print("SSIP: {}, SSP:{}".format(SSIP,SSP))
        #calculating Standard deviation of flow packets and flow bytes
        packet_set=list()
        byte_set=list()
        #calculating mean
        for flow in flows:
            packet_set.append(flow.packet_count)
            byte_set.append(flow.byte_count)
        SDFP=np.std(packet_set)
        SDFB=np.std(byte_set)
        print("packet standardization:{}, byte standardization: {}\n".format(SDFP,SDFB))
        
        SFE=len(flows)/self.time_interval

        int_flow_set=set()
        for ip_src in ip_src_set:
            if ip_src not in ip_dst_set:
                int_flow_set.add(ip_src)
        int_flow_num=len(int_flow_set)
        RFIP=(2*int_flow_num)/len(flows)
        print("RFIP:{}",format(RFIP))
        # print("SSIP: {}. SSP {}. SDFP: {}. SDFB: {}. SFE: {}. RFIP: {} "
        #             .format(SSIP, SSP, SDFP, SDFB,SFE, rfip))
        with open("./data/data.csv","a",newline="") as f:
            f_writer=csv.writer(f)
            f_writer.writerow([SSIP,SSP,SDFP,SDFB,SFE,RFIP,self.label])

    def log_flows_match(self, flows):
        for flow in flows:
            in_port = flow.match["in_port"]
            dst_eth = flow.match["eth_dst"]
            src_ip = flow.match["ipv4_src"]
            dst_ip = flow.match["ipv4_dst"]
            if flow.match['ip_proto'] == 1: # ICMP
                pass
            elif flow.match['ip_proto'] == 17:  # UDP 
                src_port = flow.match['udp_src']
                dst_port = flow.match['udp_dst']
            elif flow.match['ip_proto'] == 6: # TCP
                src_port  = flow.match['tcp_src']
                dst_port  = flow.match['tcp_dst']
            print("Eth Dst: {}. In Port {}. IP Src: {}. IP Dst: {}. Port Src: {}. Port Dst: {} "
                    .format(dst_eth, in_port, src_ip, dst_ip,src_port, dst_port ))






    """
    
    Switch stuff
    
    """


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

    # add a new flow(rule) to switch.
    #   priority : the packet will match the highest priority to match, then follw the action to deal with packet.
    #   match    : set the match condition, ex: 1 = msg.match['in_port']
    #                                           packet from port 1 will be match.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    
    # send the packet back to the switch and we can set actions on it.
    def send_packet_out(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = None
        # if the packet is not in queue of queue from switch to the controller
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

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

        # self.logger.info("packet in %s %s %s %s", dpid, dl_src, dl_dst, in_port)

        # # check IP Protocol and create a match for IP
        # if eth.ethertype == ether_types.ETH_TYPE_IP:
        #     ip = pkt.get_protocol(ipv4.ipv4)
        #     ip_src = ip.src
        #     ip_dst = ip.dst

        #     self.logger.info("packet in %s %s %s %s %s %s", dpid, src, dst, in_port, 
        #         ip_src, ip_dst)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][dl_src] = in_port

        if dl_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dl_dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            
            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                
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

        