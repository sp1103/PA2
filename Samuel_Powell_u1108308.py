from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.vlan import vlan
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str, str_to_bool

log = core.getLogger()

class SDNApp(object):
    def __init__(self, connection):
        self.connection = connection
        self.arp_table = {}  # Store IP -> MAC mappings
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
        if not a:
            return  # Not an ARP packet, ignore

        log.info("%s ARP %s %s => %s", dpid_to_str(dpid),
                 {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode, 'unknown'),
                 a.protosrc, a.protodst)

        if a.opcode == arp.REQUEST:  # If it’s an ARP request
            if a.protodst in self.arp_table:
                # If we know the MAC address, send an ARP reply
                self.send_arp_reply(event, a)
                return
            else:
                log.info("Unknown destination, flooding ARP request")
                self.flood_packet(event)

        elif a.opcode == arp.REPLY:  # If it’s an ARP reply
            # Learn the MAC address
            self.arp_table[a.protosrc] = a.hwsrc
            log.info("Learned %s is at %s", a.protosrc, a.hwsrc)
    
    def send_arp_reply(self, event, arp_req):
        mac = self.arp_table[arp_req.protodst]

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
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    def flood_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

class Set_Up (object):
	def __init__(self):
		core.openflow.addListeners(self)
	
	def _handle_ConnectionUp(self, event):
		log.debug("Conection %s", event.connection)
		fm = of.ofp_flow_mod()
		fm.priority -= 0x1000
		fm.match.dl_type = ethernet.ARP_TYPE
		fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
		event.connection.send(fm)
		SDNApp(event.connection)

def launch():
	log.info("Starting...")
	core.registerNew(Set_Up)
