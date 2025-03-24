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
		self.arp_table = {}
		connection.addListeners(self)
		log.debug("Intialized on %s", connection)

	def _handle_PacketIn(self, event):
		dpid = event.connection.dpid
		inport = event.port
		packet = event.parsed

		if not packet.parsed:
			log.warning("%s: ignoring unparsed packet", dpid_to_str(dpid))
			return
		
		a = packet.find('arp')
		if not a: return

		log.info("%s ARP %s %s => %s", dpid_to_str(dpid),
                 {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode, 'unknown'),
                 a.protosrc, a.protodst)
		
		if a.prototype == arp.PROTO_TYPE_ID:
			if a.hwtype == arp.HW_TYPE_ETHERNET:
				if a.protosrc != 0:

					if a.opcode == arp.REQUEST:
						if a.protodst in arp_table:
							r = arp()
							r.hwtype = a.hwtype
							r.prototype = a.prototype
							r.hwlen = a.hwlen
							r.protolen = a.protolen
							r.opcode = arp.REPLY
							r.hwdst = a.hwsrc
							r.protodst = a.protosrc
							r.protosrc = a.protodst
							mac = arp_table[a.protodst]

							r.hwsrc = mac
							e = ethernet(type=packet.type, src=event.connection.eth_addr,
                           					dst=a.hwsrc)
							e.payload = r
							if packet.type == ethernet.VLAN_TYPE: 
								v_rcv = packet.find('vlan')
								e.payload = vlan(eth_type = e.type,
                                 					payload = e.payload,
                                 					id = v_rcv.id,
                                 					pcp = v_rcv.pcp)
								e.type = ethernet.VLAN_TYPE
							log.info("%s answering ARP for %s" % (dpid_to_str(dpid), str(r.protosrc)))
							msg = of.ofp_packet_out()
							msg.data = e.pack()
							msg.actions.append(of.ofp_action_output(port =
                                                      of.OFPP_IN_PORT))
							msg.in_port = inport
							event.connection.send(msg)
							return
		
		msg = "%s flooding ARP %s %s => %s" % (dpid_to_str(dpid),
          {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
          'op:%i' % (a.opcode,)), a.protosrc, a.protodst)
		
		log.debug(msg)

		msg = of.ofp_packet_out()
		msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
		msg.data = event.ofp
		event.connection.send(msg.pack())
		return


class Set_Up (object):
	def __init__(self):
		core.openflow.addListeners(self)
	
	def _handle_ConnectionUp(self, event):
		log.debug("Conection %s", event.connection)
		if _install_flow:
			fm = of.ofp_flow_mod()
			fm.priority -= 0x1000
			fm.match.dl_type = ethernet.ARP_TYPE
			fm.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
			event.connection.send(fm)
		SDNApp(event.connection)

def launch():
	log.info("Starting...")
	core.registerNew(Set_Up)
