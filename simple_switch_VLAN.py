from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types

# port_vlan[a][b] = c => 'a' = dpid, 'b' = port number, 'c' = VLAN ID
port_vlan = {1: {1: [1, 2, 3], 2: [1, 2, 3]},
             2: {1: [1, 2, 3], 2: [1, 2, 3], 3: [1, 2, 3]},
             3: {1: [1, 2], 2: [2, 3], 3: [1, 2, 3]},
             4: {1: [2], 2: [3], 3: [2, 3]},
             5: {1: [1], 2: [2], 3: [1, 2]},
             6: {1: [1, 3], 2: [2, 3], 3: [1, 2, 3]},
             7: {1: [3], 2: [1], 3: [1, 3]},
             8: {1: [2], 2: [3], 3: [2, 3]},
             9: {1: [1, 2, 3], 2: [1, 2, 3], 3: [1, 2, 3]},
             10: {1: [1, 2], 2: [1, 3], 3: [1, 2, 3]},
             11: {1: [1], 2: [2], 3: [1, 2]},
             12: {1: [3], 2: [1], 3: [1, 3]},
             13: {1: [2, 3], 2: [1, 2], 3: [1, 2, 3]},
             14: {1: [2], 2: [3], 3: [2, 3]},
             15: {1: [1], 2: [2], 3: [1, 2]}}

# access[a] = [B] => 'a' = dpid , '[B]' = List of ports configured as Access Ports
access = {4: [1, 2],
          5: [1, 2],
          7: [1, 2],
          8: [1, 2],
          11: [1, 2],
          12: [1, 2],
          14: [1, 2],
          15: [1, 2]}

class SimpleSwitchVLAN(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchVLAN, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

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

        dst = eth.dst
        src = eth.src

        # SWITCH ID
        dpid = datapath.id
        actions = []

        # CREATE NEW DICTIONARY ENTRY IF IT DOES NOT EXIST
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Checking for VLAN Tagged Packet
        if eth.ethertype == ether_types.ETH_TYPE_8021Q:
            src_vlan = pkt.get_protocols(vlan.vlan)[0].vid
        else:
            src_vlan = port_vlan[dpid][in_port][0]
            actions = [parser.OFPActionPushVlan(), parser.OFPActionSetField(vlan_vid=(0x1000 | src_vlan))]

        # determine out_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            actions.append(parser.OFPActionOutput(out_port))

            # if the destination port is an access port, remove the VLAN tag
            if dpid in access and out_port in access[dpid] and not isinstance(actions[0], parser.OFPActionPopVlan):
                actions.insert(0, parser.OFPActionPopVlan())
        else:
            for out_port, dst_vlan in port_vlan[dpid].items():
                if src_vlan in dst_vlan and in_port != out_port:
                    actions.append(parser.OFPActionOutput(out_port))

                    # if the destination port is an access port, remove the VLAN tag
                    if dpid in access and out_port in access[dpid] and not isinstance(actions[0], parser.OFPActionPopVlan):
                        actions.insert(0, parser.OFPActionPopVlan())

        # if the packet is sent from access link
        if isinstance(actions[0], parser.OFPActionPushVlan):
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
        # if the packet is sent from trunk link
        else:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, vlan_vid=(0x1000 | src_vlan))

        # add flow entry to switch
        self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)