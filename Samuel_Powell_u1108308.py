from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [
	{"ip": IPAddr("10.0.0.5"), "mac": EthAddr("00:00:00:00:00:05"), "port": 5},
	{"ip": IPAddr("10.0.0.6"), "mac": EthAddr("00:00:00:00:00:06"), "port": 5},
]

server_index = 0

log = core.getLogger()

class SDNApp(object):
	def __init__(self, connection):
		self.connection = connection
		connection.addListeners(self)
		log.debug("Intialized on %s", connection)

	def _handle_PacketIn(self, event):
		global server_index
		packet = event.parsed

		if not packet:
			return

		if packet.type == packet.ARP_TYPE:
			arp_packet = packet.payload
			if arp_packet.opcode == arp_packet.REQUEST and arp_packet.protodst == VIRTUAL_IP:
				chosen_server = SERVERS[server_index]
				server_index = (server_index + 1) % len(SERVERS)

				log.info("ARP request for %s. Responding with %s", VIRTUAL_IP, chosen_server["ip"])

				arp_reply = of.arp()
				arp_reply.hwsrc = chosen_server["mac"]
				arp_reply.protosrc = VIRTUAL_IP
				arp_reply.hwdst = arp_packet.hwsrc
				arp_reply.protodst = arp_packet.protosrc
				arp_reply.opcode = arp_packet.REPLY

				ether_reply = packet
				ether_reply.type = packet.ARP_TYPE
				ether_reply.src = chosen_server["mac"]
				ether_reply.dst = arp_packet.hwsrc
				ether_reply.payload = arp_reply

				msg = of.ofp_packet_out()
				msg.data = ether_reply.pack()
				msg.actions.append(of.ofp_action_output(port=event.port))
				self.connection.send(msg)

				return
		elif packet.type == packet.IP_TYPE:
			ip_packet = packet.payload
			if ip_packet.dstip == VIRTUAL_IP:
				chosen_server = SERVERS[server_index]
				server_index = (server_index + 1) % len(SERVERS)

				log.info("Forwarding %s to %s", VIRTUAL_IP, chosen_server["ip"])

				self.add_flow_rule(client_port=event.port, virtual_ip=VIRTUAL_IP, server=chosen_server)

				self.add_reverse_flow_rule(client_ip=ip_packet.srcip, virtual_ip=VIRTUAL_IP, server=chosen_server)

				return

	def add_flow_rule(self, client_port, virtual_ip, server):
		msg = of.ofp_flow_mod()
		msg.match.dl_type = 0x0800
		msg.match.nw_dst = virtual_ip
		msg.actions.append(of.ofp_action_nw_addr.set_dst(server["ip"]))
		msg.actions.append(of.ofp_action_output(port=server["port"]))
		self.connection.send(msg)
		log.info("Installing flow: client (port %s) -> %s", client_port, server["ip"])

	def add_reverse_flow_rule(self, client_ip, virtual_ip, server):
		msg = of.ofp_flow_mod()
		msg.match.dl_type = 0x0800
		msg.match.nw_src = server["ip"]
		msg.match.nw_dst = client_ip
		msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
		msg.actions.append(of.ofp_action_output(port=1))
		self.connection.send(msg)
		log.info("Installing reverse flow: %s -> client (%s)", server["ip"], client_ip)


class Set_Up (object):
	def __init__(self):
		core.openflow.addListeners(self)
	
	def _handle_ConnectionUp(self, event):
		log.debug("Conection %s", event.connection)
		SDNApp(event.connection)

def launch():
	log.info("Starting...")
	core.registerNew(Set_Up)
