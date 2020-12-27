from __future__ import annotations

from typing import Union

"""
Takes messages from LNP and directs them to the correct handshake. Spawns
new handshakes as needed and dissociates them from the connection as requested.
"""
class SocketToServerDemux:
    @property
    def socket_connector(self):
        return self._socket_connector

    @socket_connector.setter
    def socket_connector(self,value):
        if hasattr(self,"_socket_connector"):
            self._socket_connector.after_packet_from_connection

    """
    factory is a callback which initializes the state for handling
    further messages from a given socket, and returns a callback which
    can be used to handle those messages and a callback which can be used to
    close the connection.

    factory's first parameter is a callback which can be used
    to send messages back to the socket. Its first parameter is the
    message tag as would be accepted by LNP. Its second parameter is the
    message body as would be accepted by LNP. It does not return data.

    factory's second parameter is a callback which can be used to
    tear down the connection. It has no parameters and does not return data.

    The first returned callback (the callback for sending a message to the server)
    has as its first parameter the message tag. Its second
    parameter is the untagged message body. It does not return data.

    The second returned callback (the callback for closing the connection to the client)
    has no parameters and does not return data.

    Emphasis on there being two distinct callbacks for closing the connection: one
    given by this demux to the factory so that the handler can choose to close the
    connection, and one given by the factory to this demux so that the demux (
    or more precisely code using the demux) can close the connection. These callbacks
    should not call each-other.
    """
    factory = lambda send_message_to_client, close_connection_to_client: None


    """
    send_message_to_server is a callback which can be used to send messages back to
    the socket. Its first parameter is the message tag (as provided by LNP).
    Its second parameter is the message body (as provided by LNP).
    It does not return data.
    """
    send_message_to_client = lambda socket, message_tag, message_body: None

    _handler_map = {}

    """
    Handles a message from a socket. Will set up a handler if needed and will
    select the appropriate handler otherwise.
    """
    def handle_message_from_client(
        self,
        socket,
        message_tag,
        message_body: Union[bytes,bytearray]):
        if not socket in self._handler_map:
            #check if this is client hello?
            def forward_message_to_client(message_tag, message_body):
                try:
                    self.send_message_to_client(socket,message_tag,message_body)
                except ConnectionResetError:
                    if socket in self._handler_map:
                        del self._handler_map[socket]
                    pass
            def close_connection_to_client():
                if socket in self._handler_map:
                    del self._handler_map[socket]
                try:
                    socket.close()
                except ConnectionResetError:
                    pass
            self._handler_map[socket] = self.factory(
                forward_message_to_server,
                close_connection_to_server)
        self._handler_map[socket][0](message_tag,message_body)

    def close_connection_to_client(socket):
        if socket in self._handler_map:
            self._handler_map[socket][1]()
            del self._handler_map[socket]
        try:
            socket.close()
        except ConnectionResetError:
            pass

"""
Takes messages from a peer and directs them to the correct handshake. Spawns
new handshakes in response to new connections and dissociates them from their
connection as requested.

received messages are expected to be appropriate for a RecipientHandshake to handle.
"""
class PeerToRecipientHandshakeDemux:
    """
    factory is a callback which initializes the state for handling
    further messages from a given sender, and returns a callback which
    can be used to handle those messages.

    factory's first parameter is a callback which can be used
    to send messages back to the peer.
    Its first parameter is the
    message tag. The second parameter is the untagged message body.
    It does not return data.

    factory's second parameter is a callback which can be used to
    tear down the connection. It has no parameters and does not return data.

    the factory's third parameter is the peer's username

    The returned callback's first parameter is the message tag. Its second
    parameter is the untagged message body. It does not return data.
    """
    factory = (lambda
        send_message_to_peer,
        close_connection_to_peer,
        peer_username: None)


    """
    send_peer_message is a callback which can be used to send messages back to
    the server. Its only parameter is the whole, tagged message.
    It does not return data.
    """
    send_message_to_peer = lambda peer_username, message_tag, message_body: None

    _handler_map = {}

    """
    Handles a message from a peer. Will set up a handler if needed and will
    select the appropriate handler otherwise.
    """
    def handle_message_from_peer(
        self,
        peer_username: str,
        message_tag,
        message_body: Union[bytes,bytearray]):
        if not peer_username in self._handler_map:
            #check if this is sender hello?
            def forward_message_to_peer(message_tag,message_body):
                self.send_message_to_peer(peer_username,messag_tag,message_body)
            def close_connection_to_peer():
                del self._handler_map[peer_username]
                #send close message?
            self._handler_map[peer_username] = self.factory(
                forward_message_to_peer,
                close_connection_to_peer,
                peer_username)
        self._handler_map[peer_username](message_tag,message_body)

"""
Takes messages from a peer and directs them to the correct handshake. Associates
handshakes to peer connections when requested by other components of the client
and dissociates handshake from their connection as requested.

Received messages are expected to be appropriate for a SenderHandshake to handle.
"""
class PeerToSenderHandshakeDemux:
    """
    factory is a callback which initializes the state for handling
    further messages from a given sender, and returns a callback which
    can be used to handle those messages.

    factory's first parameter is a callback which can be used
    to send messages back to the peer.
    Its first parameter is the
    message tag. The second parameter is the untagged message body.
    It does not return data.

    factory's second parameter is a callback which can be used to
    tear down the connection. It has no parameters and does not return data.

    the factory's third parameter is the peer's username

    The returned callback's first parameter is the message tag. Its second
    parameter is the untagged message body. It does not return data.
    """
    factory = (lambda
        send_message_to_peer,
        close_connection_to_peer,
        peer_username: None)


    """
    send_peer_message is a callback which can be used to send messages back to
    the server. Its only parameter is the whole, tagged message.
    It does not return data.
    """
    send_message_to_peer = lambda peer_username, message_tag, message_body: None

    _handler_map = {}


    """
    Accepts a callback with which to handle messages from a given recipient and
    returns a callback with which to close the connection.

    The returned callback has no parameters and does not return data.
    """
    def add_handler(peer_username:str,handler):
        def close_connection_to_peer():
            del self._handler_map[peer_username]
            #send close message?
        self._handler_map[peer_username] = handler
        return close_connection_to_peer

    """
    Handles a message from a peer. Will reject the message if no handler is
    present and will select the appropriate handler otherwise.
    """
    def handle_message_from_peer(
        self,
        peer_username: str,
        message_tag,
        message_body: Union[bytes,bytearray]):
        if not peer_username in self._handler_map:
            #send rejection?
            return
        self._handler_map[peer_username](message_tag,message_body)

"""
Takes messages from another component of the client and directs them to the
correct handshake. Spawns new handshakes when there is no existing handshake for
the message's recipient, and dissociates the handshakes from their connection as
requested.

received messages are expected to be appropriate for a RecipientHandshake to handle.
"""
class ClientToSenderHandshakeDemux:
    """
    factory is a callback which initializes the state for handling
    further messages from a given sender, and returns callbacks which can be
    used to send messages to a peer and to close the connection.

    factory's first parameter is the peer's username.

    factory's second parameter us a callback which allows the handler to close
    the connection.

    The first returned callback (the callback for sending a message to the peer)
    has as its first parameter the message tag. Its second
    parameter is the untagged message body. It does not return data.

    The second returned callback (the callback for closing the connection to the peer)
    has no parameters and does not return data.

    Emphasis on there being two distinct callbacks for closing the connection: one
    given by this demux to the factory so that the handler can choose to close the
    connection, and one given by the factory to this demux so that the demux (
    or more precisely code using the demux) can close the connection. These callbacks
    should not call each-other.
    """
    factory = (lambda
        peer_username,
        close_peer_connection: None)

    _handler_map = {}

    """
    Handles a message from a peer. Will set up a handler if needed and will
    select the appropriate handler otherwise.
    """
    def forward_message_to_peer(
        self,
        peer_username: str,
        message_text: str):
        if not peer_username in self._handler_map:
            #for closing requested by the handler,
            #so don't call the handler's close callback
            def close_connection_to_peer():
                del self._handler_map()
            self._handler_map[peer_username] = self.factory(
                peer_username,
                close_connection_to_peer)
        self._handler_map[peer_username][0](message_tag,message_body)

    #would this actually be called anywhere?
    def close_connection_to_peer(
        self,
        peer_username):
        if peer_username in self._handler_map:
            self._handler_map[peer_username][1]()
            del self._handler_map()
        raise NotImplementedError()
