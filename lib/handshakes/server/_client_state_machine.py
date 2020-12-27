from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from typing import Union
from collections import deque

from lib.protocol import PACKETS, INV_PACKETS
import lib.handshakes.server as handshake_module
from lib.handshakes.server import packets
import lib.crypt as crypt
from lib.event import Event

import os
import traceback

"""
The state machine for the client's side of the server handshake.

When it receives a message from the other componetns of the client
(through handle_client_message), it stores the message in a queue and
begins the handshake. If further messages are
received while the handshake is incomplete, they are also queued.

Its portions of the handhake are sent using the send_server_message callback, and
it receives responses through handle_server_message.

Once the handshake is complete, it uses the data from the handshake to encrypt
the messages from handle_client_message and wrap them in
in server envelopes, then sends them using send_server_message.
Any further messages received through handle_client_message are also wrapped and sent.

It also accepts any future server envelopes from the server (through handle_server_message)
and uses the data from the handshake to decrypt and unwrap them,
then transfers them to the next component of the client using send_client_message
"""
class ClientStateMachine:
    def __init__(
        self):

        self._main_state = "NOT_STARTED"
        self._username_state = "NO_USERNAME"
        self._message_queue = deque()
        self.username = None
        self.signature = None

        #events

        self.on_packet_send = Event()
        self.on_disconnect = Event()


        self.on_broadcast_received = Event()
        self.on_private_packet_received = Event()

        self.on_username_accept = Event()
        self.on_username_reject = Event()

    #starts the connection without waiting for a message.
    #has no effect if the connection has already started.
    def start_connection(self):
        if self._main_state == "NOT_STARTED":
            self._generate_and_send_client_hello()

    def send_broadcast(self,message):
        if self._main_state == "CLOSED":
            return

        self._message_queue.append(("BROADCAST",None,message))

        if self._main_state == "READY":
            self._flush_queues()
        if self._main_state == "NOT_STARTED":
            self.start_connection()

    def send_private_packet(
        self,
        recipient_username,
        serialized_packet):

        if self._main_state == "CLOSED":
            return

        self._message_queue.append(("PRIVATE",recipient_username,serialized_packet))

        if self._main_state == "READY":
            self._flush_queues()
        if self._main_state == "NOT_STARTED":
            self.start_connection()

    def set_username(self,username,signature):
        print("setting username")
        print(f"current state: {self._main_state}, {self._username_state}")
        if self._main_state == "READY":
            #probably no need to close
            raise ValueError(
                "Username already accepted. No facility to change it")
        elif self._username_state == "UNCONFIRMED_USERNAME":
            raise ValueError(
                "Cannot change username until server "
                +"rejects currently-unconfirmed username"
            )
        self.username = username
        self.signature = signature
        self._username_state = "UNCONFIRMED_USERNAME"

        if (
            self._main_state == "RECEIVE_ONLY"):
            #ready to request
            self._generate_and_send_client_authenticate()
        if self._main_state == "NOT_STARTED":
            self.start_connection()
        #else: not ready to send username, but not in a state where it
        #cannot be changed,
        #so nothing to do

    def graceful_close(self):
        #no niceties needed for the server handshake
        self._graceless_close()

    def _graceless_close(self):
        if self._main_state == "CLOSED":
            #nothing to close
            return

        #lets the connectors recurse into this without infinite recursion
        self._main_state = "CLOSED"

        self.downstream_connector.disconnect()
        self.upstream_private_connector.disconnect()
        self.upstream_broadcast_connector.disconnect()

    def handle_packet(self,packet_tag,serialized_packet):
        if self._main_state == "CLOSED":
            return
        try:
            self._dispatch_or_reject(packet_tag,serialized_packet)
        except:
            self._main_state = "CLOSED"
            self.graceful_close()
            raise

    def is_username_accepted(self):
        return self._username_state == "READY"

    def _dispatch_or_reject(
        self,
        packet_tag,
        serialized_packet):

        if (self._main_state == "WAITING_FOR_HELLO"
            and packet_tag == PACKETS["SERVER_HELLO"]):
            self._handle_server_hello(serialized_packet)
        elif (
            self._main_state == "RECEIVE_ONLY"
            and self._username_state == "UNCONFIRMED_USERNAME"
            and packet_tag == PACKETS["USERNAME_ACCEPT"]):
            self._handle_username_accept()
        elif (
            self._main_state == "RECEIVE_ONLY"
            and self._username_state == "UNCONFIRMED_USERNAME"
            and packet_tag == PACKETS["USERNAME_REJECT"]):
            self._handle_username_reject()
        elif (
            (
                self._main_state == "READY"
                or self._main_state == "RECEIVE_ONLY"
            )
            and packet_tag == PACKETS["SERVER_ENVELOPE"]):
            self._handle_downstream_private_packet(serialized_packet)
        elif (
            (
                self._main_state == "READY"
                or self._main_state == "RECEIVE_ONLY"
            )
            and packet_tag == PACKETS["DISTRIBUTE_SERVER_BROADCAST"]):
            self._handle_downstream_broadcast(serialized_packet)
        else:
            raise ValueError(
                f"Unexpected packet tag {INV_PACKETS[packet_tag]}"
                +"\n\t"
                +f"Current main state: {self._main_state}"
                +"\n\t"
                +f"Current username state: {self._username_state}")

    def _flush_queues(self):
        #unified queue to ensure message ordering
        for message_type, recipient, packet in self._message_queue:
            if message_type == "PRIVATE":
                self._generate_and_send_downstream_private_packet(
                    recipient,
                    packet)
            elif message_type == "BROADCAST":
                self._generate_and_send_downstream_broadcast(packet)

        self._message_queue.clear()

    def _generate_parameters(self):
        self.client_random = os.urandom(packets.handshake_module.RANDOM_LENGTH)
        self.client_ephemeral_private_key = X25519PrivateKey.generate()
        self.client_ephemeral_public_key = self.client_ephemeral_private_key.public_key()
        pass

    def _generate_and_send_client_hello(self):
        self._generate_parameters()

        hello = packets.ClientHello(
            self.client_ephemeral_public_key,
            self.client_random)

        serialized_hello = hello.serialize()

        self._main_state = "WAITING_FOR_HELLO"

        self.on_packet_send.invoke(
            PACKETS["CLIENT_HELLO"],
            serialized_hello)

    def _handle_server_hello(
        self,
        serialized_hello):

        server_hello = packets.ServerHello.validate_and_deserialize(
            serialized_hello,
            self.client_random)

        self.server_random = server_hello.server_random
        self.server_ephemeral_public_key = server_hello.server_ephemeral_public_key

        premaster_key = self.client_ephemeral_private_key.exchange(
            self.server_ephemeral_public_key)

        master_key = (HKDF(
            algorithm = hashes.SHA256(),
            length = handshake_module.MASTER_KEY_LENGTH,
            salt = self.client_random + self.server_random,
            info = None)
            .derive(premaster_key))

        #For testing -- the key bytes cannot be extracted from the
        #ChaCha20Poly1305 object, and ChaCha20Poly1305 cannot be compared for
        #equality
        self._client_send_key_bytes = master_key[0:crypt.CHACHA20_KEY_LENGTH]
        self._server_send_key_bytes = master_key[crypt.CHACHA20_KEY_LENGTH:]

        self.client_send_key = ChaCha20Poly1305(self._client_send_key_bytes)
        self.server_send_key = ChaCha20Poly1305(self._server_send_key_bytes)

        self._main_state = "RECEIVE_ONLY"

        if self._username_state == "UNCONFIRMED_USERNAME":
            self._generate_and_send_client_authenticate()

    def _generate_and_send_client_authenticate(self):
        client_authenticate = packets.ClientAuthenticate(
            self.username,
            self.signature)
        serialized_packet = client_authenticate.encrypt_and_serialize(
            self.client_send_key)

        self.on_packet_send.invoke(
            PACKETS["CLIENT_AUTHENTICATE"],
            serialized_packet)

    def _handle_username_accept(self):
        self._main_state = "READY"
        self._username_state = "READY"
        self.on_username_accept.invoke()
        self._flush_queues()

    def _handle_username_reject(self):
        self._username_state = "NO_USERNAME"
        self.username = None
        self.signature = None
        self.on_username_reject.invoke()

    def _handle_downstream_private_packet(
        self,
        serialized_envelope):

        server_envelope = packets.ServerEnvelope.decrypt_and_deserialize(
            serialized_envelope,
            self.server_send_key)

        sender_username = server_envelope.username
        private_packet = server_envelope.private_packet

        self.on_private_packet_received.invoke(
            sender_username,
            private_packet)

    def _generate_and_send_downstream_private_packet(
        self,
        recipient_username,
        private_packet):

        server_envelope = packets.ServerEnvelope(
            recipient_username,
            private_packet)

        serialized_packet = server_envelope.encrypt_and_serialize(
            self.client_send_key)

        self.on_packet_send.invoke(
            PACKETS["SERVER_ENVELOPE"],
            serialized_packet
        )

    def _handle_downstream_broadcast(
        self,
        serialized_broadcast):

        #when receiving from downstream,
        #broadcast is DistributeBroadcast and includes sender information
        broadcast = packets.DistributeBroadcast.decrypt_and_deserialize(
            serialized_broadcast,
            self.server_send_key)

        sender_username = broadcast.sender_username
        message = broadcast.message

        self.on_broadcast_received.invoke(
            sender_username,
            message)

    def _generate_and_send_downstream_broadcast(
        self,
        message):

        #when receiving from up,
        #broadcast is SendBroadcast and lacks sender information.
        #server uses the previously-verified username
        broadcast = packets.SendBroadcast(
            message)

        serialized_broadcast = broadcast.encrypt_and_serialize(
            self.client_send_key)

        self.on_packet_send.invoke(
            PACKETS["SEND_SERVER_BROADCAST"],
            serialized_broadcast)
