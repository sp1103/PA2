from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class SDNApp(object):
	def __init__(self, connection):
		self.connection = connection
		connection.addListeners(self)
		log.debug("Intialized on %s", connection)

	def _handle_PacketIn(self, event):
		packet = event.parsed
		log.debug("PacketIn: %s", packet)


class Set_Up (object):
	def __init__(self):
		core.openflow.addListeners(self)
	
	def _handle_ConnectionUp(self, event):
		log.debug("Conection %s", event.connection)
		SDNApp(event.connection)

def launch():
	log.info("Starting...")
	core.registerNew(Set_Up)
