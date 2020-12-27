from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

from typing import Union
from collections import deque

from lib.protocol import PACKETS, INV_PACKETS
import lib.handshakes.server as handshake_module
from lib.handshakes.server import packets
import lib.crypt as crypt
from lib.event import Event

import os

"""
The state machine for the server's side of the server handshake.

When it receives a message from the client
(through handle_client_message), it begins the handshake.

Its portions of the handhake are sent using the send_client_message callback, and
it receives responses through handle_client_message.

Once the handshake is complete, it uses the data from the handshake to encrypt
the messages from handle_server_message and wrap them in
in server envelopes, then sends them using send_client_message.
Any further messages received through handle_server_message are also wrapped and sent.

It also accepts any future server envelopes from the client (through handle_client_message)
and uses the data from the handshake to decrypt and unwrap them,
then transfers them to the next component of the server using send_server_message
"""
class ServerStateMachine:
    def __init__(
        self,
        server_persistent_private_key,
        ca_persistent_public_key):

        self._state = "WAITING_FOR_HELLO"
        self._message_queue = deque()

        self.server_persistent_private_key = server_persistent_private_key
        self.server_persistent_public_key = server_persistent_private_key.public_key()
        self.ca_persistent_public_key = ca_persistent_public_key

        #events
        self.on_packet_send = Event()
        self.on_disconnect = Event()


        self.on_broadcast_received = Event()
        self.on_private_packet_received = Event()

        self.on_username_requested = Event()

    def send_broadcast(
        self,
        sender_username: str,
        message:str):

        if self._state == "CLOSED":
            return

        self._message_queue.append(("BROADCAST",sender_username,message))

        if (
            self._state == "READY"
            or self._state == "WAITING_FOR_AUTHENTICATE"):
            self._flush_queues()

    def send_private_packet(
        self,
        sender_username,
        serialized_packet:Union[bytes,bytearray]):

        if self._state == "CLOSED":
            return

        self._message_queue.append(("PRIVATE",sender_username,serialized_packet))

        if (
            self._state == "READY"
            or self._state == "WAITING_FOR_AUTHENTICATE"):
            self._flush_queues()

    def graceful_close(self):
        #no niceties needed for the server handshake
        self._graceless_close()

    def _graceless_close(self):
        if self._state == "CLOSED":
            #nothing to close
            return

        #lets the connectors recurse into this without infinite recursion
        self._state = "CLOSED"

        self.on_disconnect.invoke()

    def accept_username(self):
        if self._state != "WAITING_FOR_CONFIRM":
            raise ValueError(
                "Handshake is not waiting to confirm a username")
        self._state = "READY"
        self._generate_and_send_username_accept()

    def reject_username(self):
        if self._state != "WAITING_FOR_CONFIRM":
            raise ValueError(
                "Handshake is not waiting to confirm a username")
        self._generate_and_send_username_reject()

    def handle_packet(self,packet_tag,serialized_packet):
        if self._state == "CLOSED":
            return
        try:
            self._dispatch_or_reject(packet_tag,serialized_packet)
        except:
            self._state = "CLOSED"
            self.graceful_close()
            raise

    def _dispatch_or_reject(
        self,
        packet_tag,
        serialized_packet):

        if (self._state == "WAITING_FOR_HELLO"
            and packet_tag == PACKETS["CLIENT_HELLO"]):
            self._handle_client_hello(serialized_packet)
        elif (self._state == "WAITING_FOR_AUTHENTICATE"
            and packet_tag == PACKETS["CLIENT_AUTHENTICATE"]):
            self._handle_client_authenticate(serialized_packet)
        elif (self._state == "READY"
            and packet_tag == PACKETS["SERVER_ENVELOPE"]):
            self._handle_downstream_private_packet(serialized_packet)
        elif (self._state == "READY"
            and packet_tag == PACKETS["SEND_SERVER_BROADCAST"]):
            self._handle_downstream_broadcast(serialized_packet)
        else:
            raise ValueError(
                f"Unexpected packet tag {INV_PACKETS[packet_tag]}\n\t"
                +f"Current State: {self._state}")

    def _flush_queues(self):
        #a combined queue is used to maintain message ordering
        for message_type, sender_username, data in self._message_queue:
            if message_type == "BROADCAST":
                self._generate_and_send_downstream_broadcast(
                    sender_username,
                    data)
            elif message_type == "PRIVATE":
                self._generate_and_send_downstream_private_packet(
                    sender_username,
                    data)

    def _generate_parameters(self):
        self.server_random = os.urandom(packets.handshake_module.RANDOM_LENGTH)
        self.server_ephemeral_private_key = X25519PrivateKey.generate()
        self.server_ephemeral_public_key = self.server_ephemeral_private_key.public_key()
        pass

    def _handle_client_hello(
        self,
        serialized_hello):

        self._generate_parameters()

        hello = packets.ClientHello.deserialize(serialized_hello)

        self.client_random = hello.client_random
        self.client_ephemeral_public_key = hello.client_ephemeral_public_key

        premaster_key = self.server_ephemeral_private_key.exchange(
            self.client_ephemeral_public_key)

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

        self._state = "WAITING_FOR_AUTHENTICATE"
        self._generate_and_send_server_hello()
        self._flush_queues()

    def _generate_and_send_server_hello(self):
        hello = packets.ServerHello(
            self.server_ephemeral_public_key,
            self.server_persistent_public_key,
            self.server_random,
            self.client_random)

        serialized_hello = hello.sign_and_serialize(
            self.server_persistent_private_key)

        self.on_packet_send.invoke(
            PACKETS["SERVER_HELLO"],
            serialized_hello)

    def _handle_client_authenticate(self, serialized_packet):
        try:
            client_authenticate = packets.ClientAuthenticate.decrypt_deserialize_and_validate(
                serialized_packet,
                self.client_send_key,
                self.ca_persistent_public_key)
        except:
            self._generate_and_send_username_reject()
            return

        self.username = client_authenticate.username

        #TODO: what should happen if it gets this between receiving a previous authenticate
        #and having the username confirmed?

        #username may already ahave been accepted
        if self._state != "READY":
            self._state = "WAITING_FOR_CONFIRM"


        self.on_username_requested.invoke(self,self.username)

    def _generate_and_send_username_accept(self):
        self.on_packet_send.invoke(
            PACKETS["USERNAME_ACCEPT"],
            bytes())

    def _generate_and_send_username_reject(self):
        self.on_packet_send.invoke(
            PACKETS["USERNAME_REJECT"],
            bytes())

    def _handle_downstream_private_packet(
        self,
        serialized_envelope):

        envelope = packets.ServerEnvelope.decrypt_and_deserialize(
            serialized_envelope,
            self.client_send_key)

        recipient_username = envelope.username
        private_packet = envelope.private_packet

        self.on_private_packet_received.invoke(
            #sender
            self.username,
            recipient_username,
            private_packet)

    def _generate_and_send_downstream_private_packet(
        self,
        sender_username,
        private_packet):

        envelope = packets.ServerEnvelope(
            sender_username,
            private_packet)

        serialized_envelope = envelope.encrypt_and_serialize(
            self.server_send_key)

        self.on_packet_send.invoke(
            PACKETS["SERVER_ENVELOPE"],
            serialized_envelope
        )

    def _handle_downstream_broadcast(
        self,
        serialized_broadcast):

        #when receiving from downstream,
        #broadcast is SendBroadcast and does not include sender information.
        #server uses the previously-verified username.
        broadcast = packets.SendBroadcast.decrypt_and_deserialize(
            serialized_broadcast,
            self.client_send_key)

        message = broadcast.message

        self.on_broadcast_received.invoke(
            self.username,
            message)

    def _generate_and_send_downstream_broadcast(
        self,
        sender_username,
        message):

        #when receiving from upstream,
        #broadcast is DistributeBroadcast and has sender information.
        broadcast = packets.DistributeBroadcast(
            sender_username,
            message)

        serialized_broadcast = broadcast.encrypt_and_serialize(
            self.server_send_key)

        self.on_packet_send.invoke(
            PACKETS["DISTRIBUTE_SERVER_BROADCAST"],
            serialized_broadcast)
