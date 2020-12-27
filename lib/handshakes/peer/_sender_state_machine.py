from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  #added for encryption


from typing import Union
import struct  #used for unpacking
import os  #used for random bytes with .urandom(bytes)
from collections import deque
from lib.protocol import PACKETS, INV_PACKETS
import lib.handshakes.peer as handshake_module
from lib.handshakes.peer import peer_packets
import lib.crypt as crypt
from lib.event import Event

_TAG_FORMAT = "b"
_NONCE_FORMAT = "12s"
_RANDOM_LENGTH = 16
_RANDOM_FORMAT = f"{_RANDOM_LENGTH}s"
_X25519_KEY_FORMAT = "32s"
_RSA_SIGNATURE_FORMAT = "256s"
handshake_module.RSA_SIGNATURE_LENGTH = 256
crypt.CHACHA20_KEY_LENGTH = 32

#in theory, we could have one handshake object which handles both sending and
#receiving and which can play either role in the handshake, but it is likely
#easier to have them completely separate and to have another component
#discriminate between messages which are part of one handshake versus the other.
#this has the consequence that there can be two logicical connections between
#two peers -- one for each direction.
def extract_tag(tagged_message):
    serialized_message_length = len(tagged_message) - struct.calcsize(_TAG_FORMAT)
    message_tag, serialized_message = struct.unpack(
        f"{_TAG_FORMAT}{serialized_message_length}s",
        tagged_message)
    return (message_tag, serialized_message)
"""
The state machine for the sender's side of the peer handshake.

When it receives a message from another component of the client
(through handle_client_message), it stores the message in a queue and
begins the handshake. If further messages are received while
the handshake is incomplete, they are also queued.

Its portions of the handhake are sent using the send_peer_message callback, and
it receives responses through handle_peer_message.

Once the handshake is complete, it uses the data from the handshake to encrypt
the messages from handle_client_message and wrap them in
in peer envelopes, then sends them using send_peer_message.
Any further messages received through handle_client_message are also wrapped and sent.
"""

class SenderStateMachine:
    def __init(
        self,
        client_username: str,
        peer_username: str):
        self.peer_username = peer_username
        self.client_username = client_username
        self._queue = deque()

        #events 
        self.on_packet_send_to_peer = Event()
        self.on_disconnect = Event()
        
        self.on_private_packet_received = Event()

    """
    Recieves a message "from the wire".

    message_body is the "message body" from the server envelope
    as the type bytes (or bytes-like).
    sender is the username of the peer which sent the message.

    Messages will be ignored if this class has seen fit to call
    close_peer_connection
    """
    
    def handle_message_from_peer(
        self,
        message_tag,
        serialized_message: Union[bytes, bytearray])->None:
        if self._state == "CLOSED":
            return
        try:
            self._dispatch_or_reject(message_tag,serialized_message)
        except:
            self.graceful_close()
            raise

    def _dispatch_or_reject(self,message_tag,serialized_message):
        if(self._state == "CLOSED"):
            pass
        elif(self._state == "WAITING_FOR_HELLO"
             and message_tag == PACKETS["RECIPIENT_HELLO"]):
             self._handle_recipient_hello(serialized_message)
        elif(message_tag == PACKETS["CLOSE_PEER_CONNECTION"]):
            self.on_disconnect.invoke()
            # staticmethod(self.hard_disconnect).__func__()
            self._state == "CLOSED"
        else:
            raise  NotImplementedError()
            

    """
    Receives a message from another component of the client
    to be encrypted and sent "down the wire"
    towards the peer.

    messages are queued if they cannot be sent immediately (that is,
    if the handshake is not complete.)

    Messages will be ignored if this class has seen fit to call
    close_peer_connection
    """

    def start_connection(self):
        if self._state == "NOT_STARTED":
            self._generate_and_send_sender_hello()
            self._state = "WAITING_FOR_HELLO"

    def forward_message_to_peer(
        self,
        peer_username,
        message_body: str)->None:
        self._queue.append(message_body)
        if self._state == "READY":
            self._flush_queue()
        if self._state == "NOT_STARTED":
            self.start_connection()

    def _handle_recipient_hello(self,serialized_message):
        #TODO modify to use events for recieving packets 
        recipient_hello = handshake_module.RecipientHello.deserialize(serialized_message)
        self.recipient_ephemeral_public_key = recipient_hello.recipient_ephemeral_public_key
        self.recipient_random = recipient_hello.recipient_random
        self._derive_send_key()
        self._flush_queue()
        self._state = "READY"
        
    def _flush_queue(self):
        for message in self._queue:
            self._generate_and_send_peer_envelope(message)
        self._queue.clear()

    def _derive_send_key(self):
        premaster_key = self.sender_ephemeral_private_key.exchange(
        self.recipient_ephemeral_public_key)
        self.send_key = HKDF(
            algorithm = hashes.SHA256(),
            length = crypt.CHACHA20_KEY_LENGTH,
            salt = self.recipient_random + self.sender_random,
            info = None)

    def _generate_parameters(self):
        self.sender_random = os.urandom(_RANDOM_LENGTH)
        self.sender_ephemeral_private_key = X25519PrivateKey.generate()
        self.sender_ephemeral_public_key = self.sender_ephemeral_private_key.public_key()

    def _generate_and_send_sender_hello(self):
        self._generate_parameters()
        sender_hello = handshake_module.SenderHello(
            self.client_username,
            self.sender_ephemeral_public_key,
            self.sender_random)
        serialized_message = sender_hello.serialize()
        self.on_packet_send_to_peer.invoke(
            self.peer_username,
            PACKETS["SENDER_HELLO"],
            serialized_message)
        # staticmethod(self.send_serialized_message_to_peer).__func__(
        #     self.peer_username,
        #     PACKETS["SENDER_HELLO"],
        #     serialized_message)
    
    def _generate_and_send_peer_envelope(self, wrapped_message):
        peer_envelope = handshake_module.PeerEnvelope(self,wrapped_message)
        serialized_message = peer_envelope.encrypt_and_serialize(self.send_key)
           
        self.on_packet_send_to_peer.invoke(
            self.peer_username,
            PACKETS["PEER_ENVELOPE"],
            serialized_message)
        # staticmethod(self.send_serialized_message_to_peer).__func__(
        #     self.peer_username,
        #     PACKETS["PEER_ENVELOPE"],
        #     serialized_message)
        
    def graceful_close(self):
        if self._state == "CLOSED":
            return
        elif self._state == "NOT_STARTED":
            self.on_disconnect.invoke()
            # staticmethod(self.hard_disconnect).__func__()
            self._state = "CLOSED"
        else:
            self.on_packet_send_to_peer.invoke(
            self.peer_username,
            PACKETS["CLOSE_PEER_CONNECTION"],
            bytes())
            # staticmethod(self.send_serialized_message_to_peer).__func__(
            #     self.peer_username,
            #     PACKETS["CLOSE_PEER_CONNECTION"],
            #     bytes())
            self._state = "CLOSED"
        