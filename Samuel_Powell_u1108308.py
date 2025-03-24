from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str

log = core.getLogger()

class SDNApp(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # Maps IP -> (MAC, Port)
        connection.addListeners(self)
        log.debug("Initialized on %s", connection)

    def _handle_PacketIn(self, event):
        dpid = event.connection.dpid
        inport = event.port
        packet = event.parsed

        if not packet.parsed:
            log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
            return
        
        a = packet.find('arp')
        if a:
            self.handle_arp(event, a)
            return
        
        ip = packet.find('ipv4')
        if ip:
            self.handle_ip(event, ip, packet)
            return

    def handle_arp(self, event, a):
        dpid = event.connection.dpid
        inport = event.port

        log.info("%s ARP %s %s => %s", dpid_to_str(dpid),
                 {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode, 'unknown'),
                 a.protosrc, a.protodst)

        # Learn the MAC and port
        self.arp_table[a.protosrc] = (a.hwsrc, inport)

        if a.opcode == arp.REQUEST:
            if a.protodst in self.arp_table:
                self.send_arp_reply(event, a)
            else:
                log.info("Unknown ARP target, flooding request")
                self.flood_packet(event)

    def send_arp_reply(self, event, arp_req):
        mac, _ = self.arp_table[arp_req.protodst]

        r = arp()
        r.hwtype = arp_req.hwtype
        r.prototype = arp_req.prototype
        r.hwlen = arp_req.hwlen
        r.protolen = arp_req.protolen
        r.opcode = arp.REPLY
        r.hwdst = arp_req.hwsrc
        r.protodst = arp_req.protosrc
        r.protosrc = arp_req.protodst
        r.hwsrc = mac

        e = ethernet(type=ethernet.ARP_TYPE, src=mac, dst=arp_req.hwsrc)
        e.payload = r

        log.info("Sending ARP reply: %s is at %s", r.protosrc, r.hwsrc)

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(msg)

    def flood_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def handle_ip(self, event, ip, packet):
        dpid = event.connection.dpid
        inport = event.port

        # Learn source MAC and port
        self.arp_table[ip.srcip] = (packet.src, inport)

        if ip.dstip in self.arp_table:
            mac, outport = self.arp_table[ip.dstip]

            # Forward the packet to the learned destination
            log.info("Forwarding packet to %s via port %d", ip.dstip, outport)
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_type=0x0800, nw_dst=ip.dstip)
            msg.actions.append(of.ofp_action_output(port=outport))
            event.connection.send(msg)

            # Send the packet
            pkt_out = of.ofp_packet_out()
            pkt_out.data = event.ofp
            pkt_out.actions.append(of.ofp_action_output(port=outport))
            event.connection.send(pkt_out)
        else:
            log.info("Unknown destination %s, flooding", ip.dstip)
            self.flood_packet(event)

class Set_Up(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s", event.connection)
        SDNApp(event.connection)

def launch():
    log.info("Starting...")
    core.registerNew(Set_Up)
