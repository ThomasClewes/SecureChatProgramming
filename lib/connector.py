"""module doc string that outlines the document"""
from collections import deque
from lib.event import Event
import lib.LNP as lnp
# from lib.protocol import INV_PACKETS

#intended to reduce callback hell a bit
class Connector:
    """ class docstring information"""
    def __init__(self):
        self.before_disconnect: Event = Event()
        self.after_disconnect: Event = Event()

        self.before_send: Event = Event()
        self.after_send: Event = Event()

        self.before_receive: Event = Event()
        self.after_receive: Event = Event()

        self.is_disconnected = False


    def disconnect(self):
        """ function docstring information"""
        self.before_disconnect.invoke()
        if not self.is_disconnected:
            self._on_disconnect(False)
            self.after_disconnect.invoke()

    #override me
    def _on_disconnect(self, socket):
        """ function docstring information"""
        if socket:
            self.is_disconnected = True
        self.is_disconnected = True

    def send(
            self,
            *data):
        """ function docstring information"""

        self.before_send.invoke(*data)
        if self._should_send(*data):
            self._on_send(*data)
            self.after_send.invoke(*data)

    def _should_send(self, *data):
        if data :
            return self.is_disconnected
        return not self.is_disconnected

    #override me
    def _on_send(
            self,
            socket,
            packet_tag,
            packet_body):
        pass

    #should be called by derived class when data comes from the connection
    def _receive(
            self,
            *data):
        self.before_receive.invoke(*data)
        if self._should_receive():
            self._on_receive(*data)
            self.after_receive.invoke(*data)

    def _should_receive(self, *data):
        if data:
            return not self.is_disconnected
        return not self.is_disconnected

    #override me
    def _on_receive(
            self,
            *data):
        pass

#allows code to give already-retrieved data to the connector
class GenericConnector(Connector):
    """" class docstring information"""
    # def __init__(self):
        # super().__init__()
    def handle_data_from_connection(
            self,
            *data):
        """ function docstring information"""
        if data:
            return self.is_disconnected
        self._receive()

class LnpConnector(Connector):
    """ class docstring information"""
    def __init__(self):
        super().__init__()
        self.on_exceptional_socket = Event()

        #since send may not
        self.send_queue = deque()
        self.send_backup = None

        self.receive_buffers = {}
        self.receive_lengths = {}
        self.packet_lengths = {}
        self.packet_tags = {}

    def handle_readable_socket(self, socket):
        """ function docstring information"""
        if self.is_disconnected:
            return
        try:
            status = lnp.recv(
                socket,
                self.receive_buffers,
                self.receive_lengths,
                self.packet_lengths,
                self.packet_tags)
        except BaseException:
            self.on_exceptional_socket.invoke(socket)
            #return
            raise

        if status == "MSG_CMPLT":
            self.__receive(socket)
        elif status == "ERROR":
            self.on_exceptional_socket.invoke(socket)

    def __receive(self, socket):
        """ function docstring information"""
        print("receive call")
        packet_tag, packet = lnp.get_msg_from_queue(
            socket,
            self.receive_buffers,
            self.receive_lengths,
            self.packet_lengths,
            self.packet_tags,
            None)
        super()._receive(socket, packet_tag, packet)

    def handle_exceptional_socket(self, socket):
        """ function docstring information"""
        self.on_exceptional_socket.invoke(socket)

    def _on_disconnect(self, socket):
        """ function docstring information"""
        socket.close()
        super()._on_disconnect(socket)

    def _on_send(
            self,
            socket,
            packet_tag,
            packet_body):
        """ function docstring information"""
        print("Send call")

        lnp.send(
            socket,
            message=packet_body,
            id=packet_tag)

#Allows mutual recursion without blowing stacks, long stack traces,
#components stealing the thread perpetually, etc.
class TrampolineConnector(GenericConnector):
    """ class docstring information"""

    def __init__(self):
        super().__init__()
        self._event_queue = deque()

    def disconnect(self):
        self._event_queue.append(("DISCONNECT", None))

    def _disconnect(self):
        super().disconnect()

    def send(
            self,
            *packet_data):
        self._event_queue.append(("SEND", packet_data))

    def _receive(
            self,
            *packet_data):
        self._event_queue.append(("RECEIVE", packet_data))

    def pump(self):
        """ function docstring information"""
        if len(self._event_queue) == 0:
            return False

        type_of, packet_data = self._event_queue.popleft()
        if type_of == "DISCONNECT":
            self._disconnect()
        elif type_of == "SEND":
            super().send(*packet_data)
        elif type_of == "RECEIVE":
            super()._receive(*packet_data)
        return True
