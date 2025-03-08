from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class SDNApp(object):
	def __init__(self, connection):
		self.connection = conection
		connection.addListeners(self)
		log.debug("Intialized on %s", connection)

	def _handle_packetIn(self, event):
		packet = event.parsed
		log.debug("PacketIn: %s", packet)

	def launch():
		def start_switch(event):
			log.info("Switch %s has connected", evvent.connection)
			SDNApp(event.connection)
		core.openflow.addListenerByName("ConnectionUp", start_switch)
