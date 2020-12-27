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

"""
The state machine for the sender's side of the peer handshake.

When it receives a message from the peer (through handle_peer_message),
it begins the handshake.

Its portions of the handhake are sent using the send_peer_message callback, and
it receives responses through handle_peer_message.

Once the handshake is complete, it accepts peer envelopes from the peer
(through handle_peer_message) and uses the data from the handshake to
decrypt and unwrap them, then transfers them to the next component of
the client using send_client_message
"""
class RecipientHandshake:
    def __init__ (
        self,
        peer_username):
        self.peer_username = peer_username

        # events
        self.on_packet_send_to_client = Event()
        self.on_packet_send_to_peer = Event()
        self.on_disconnect = Event()
        self.on_private_packet_received = Event()

    """
    Recieves a message "from the wire".

    message_body is the "message body" from the server envelope
    as the type bytes (or a bytes-like type).
    sender is the username of the peer which sent the message.

    Messages will be ignored if this class has seen fit to call
    close_peer_connection
    """
    def handle_serialized_message_from_peer(
        self,
        message_tag,
        sender: str,
        message_body: Union[bytes, bytearray])->None:
        try:
            self._dispatch_or_reject(message_tag,message_body)
        except:
            #TODO change to new method with events 
            staticmethod(self.close_connection_to_peer).__func__()
            raise

    def _dispatch_or_reject(self,message_tag,message_body):
        if(self._state == "CLOSED"):
            pass
        elif(self._state == "READY" 
            and message_tag == PACKETS["PEER_ENVELOPE"]):
            self._handle_peer_envelope(message_body)
        elif(self._state == "NOT_STARTED"
             and message_tag == PACKETS["SENDER_HELLO"]):
             self._handle_sender_hello(message_body)
        elif(message_tag == PACKETS["CLOSE_PEER_CONNECTION"]):
            self.on_disconnect.invoke()
            # staticmethod(self.hard_disconnect).__func__()
            self._state == "CLOSED"
        else:
            return NotImplementedError()

    def _handle_peer_envelope(self,message_body):
        peer_envelope = handshake_module.PeerEnvelope(message_body)
        packet = peer_envelope.encrypt_and_serialize(self.send_key)
        #should this inclued peer_username or client?
        self.on_packet_send_to_client.invoke(self.peer_username,packet)
        # staticmethod(self.forward_message_to_client).__func__(self.peer_username, packet)

    def _derive_send_key(self):
        premaster_key = self.recipient_ephemeral_private_key.exchange(
        self.sender_ephemeral_public_key)
        self.send_key = HKDF(
            algorithm = hashes.SHA256(),
            length = crypt.CHACHA20_KEY_LENGTH,
            salt = self.recipient_random + self.sender_random,
            info = None)

    def _handle_sender_hello(self,serialized_message):
        self._generate_parameters()
        sender_hello = handshake_module.SenderHello.deserialize(serialized_message)
        self.sender_ephemeral_public_key = sender_hello.sender_ephemeral_public_key
        self.sender_random = sender_hello.sender_random
        self._derive_send_key()
        self._generate_and_send_recipient_hello()
        self._state == "READY"
    
    def _generate_and_send_recipient_hello(self):
        recipient_hello = handshake_module.RecipientHello(
            self.recipient_ephemeral_public_key,
            self.recipient_random)
        serialized_message = recipient_hello.serialize()
        self.on_packet_send_to_peer.invoke(
            self.peer_username,
            PACKETS["RECIPIENT_HELLO"],
            serialized_message)
        # staticmethod(self.send_serialized_message_to_peer).__func__(
        #     self.peer_username,
        #     PACKETS["RECIPIENT_HELLO"],
        #     serialized_message)

    def _generate_parameters(self):
        self.recipient_random = os.urandom(_RANDOM_LENGTH)
        self.recipient_ephemeral_private_key = X25519PrivateKey.generate()
        self.recipient_ephemeral_public_key = self.recipient_ephemeral_private_key.public_key()