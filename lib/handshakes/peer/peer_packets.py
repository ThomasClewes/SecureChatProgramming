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
from lib.protocol import PACKETS

_TAG_FORMAT = "b"
_NONCE_FORMAT = "12s"
_RANDOM_LENGTH = 16
_RANDOM_FORMAT = f"{_RANDOM_LENGTH}s"
_X25519_KEY_FORMAT = "32s"
_RSA_SIGNATURE_FORMAT = "256s"
handshake_module.RSA_SIGNATURE_LENGTH = 256
crypt.CHACHA20_KEY_LENGTH = 32

"""
Represents the untagged part of the "sender hello" message.
See Notes/ABI/Peer Handshake.txt
"""

#update to include sender_username in serialization
# at the end to avoid the need for and explicit size field
class SenderHello:
    def __init__(
            self,
            sender_ephemeral_public_key: X25519PublicKey,
            sender_random: Union[bytes, bytearray]):

        #public key
        sender_random = bytes(sender_random)
        self.sender_ephemeral_public_key = sender_ephemeral_public_key
        self.sender_random = sender_random

    """
    Formats the message information into an array of bytes as described in
    Notes/ABI/Peer Handshake.txt
    """
    def serialize(self)->Union[bytes,bytearray]:
        #packs temp public key and the sender random bytes int a message var
        wrapped_message = struct.pack(
            f"32s16s",
            self.sender_ephemeral_public_key,
            self.sender_random)

        return wrapped_message

    """
    Accepts a message which is formatted as an array of bytes and parses it into
    a python object as described in Notes/ABI/Peer Handshake.txt
    """
    @staticmethod
    def deserialize(serialized_message: Union[bytes, bytearray])->SenderHello:
        #unpacks message into a list of unpacked message
        #add consts for 32 and 16
        #use struct.calcsize
        (
            sender_ephemeral_public_key_bytes,
            sender_random_data
        ) = struct.unpack(
            f"32s16s",
            serialized_message)

        sender_ephemeral_public_key = X25519PublicKey.from_public_bytes(
            sender_ephemeral_public_key_bytes)

        return SenderHello(
            sender_ephemeral_public_key,
            sender_random_data)


"""
Represents the untagged part of the "recipient hello" message.
See Notes/ABI/Peer Handshake.txt
"""
class RecipientHello:
    def __init__(
            self,
            recipient_ephemeral_public_key: X25519PublicKey,
            recipient_random: Union[bytes, bytearray]):

        recipient_random = bytes(recipient_random)
        self.recipient_ephemeral_public_key = recipient_ephemeral_public_key
        self.recipient_random = recipient_random

    """
    Formats the message information into an array of bytes as described in
    Notes/ABI/Peer Handshake.txt
    """
    def serialize(self)->Union[bytes,bytearray]:
        #add consts for 32 and 16
        #use struct.calcsize
        serialized_message = struct.pack(
            "32s16s",
            self.recipient_ephemeral_public_key,
            self.recipient_random)

        return serialized_message

    """
    Accepts a message which is formatted as an array of bytes and parses it into
    a python object as described in Notes/ABI/Peer Handshake.txt
    """
    @staticmethod
    def deserialize(serialized_message: Union[bytes,bytearray])->RecipientHello:
                #unpacks message into a list of unpacked message
        #add consts for 32 and 16
        #use struct.calcsize
        (
            recipient_ephemeral_public_key_bytes,
            recipient_random_data
        ) = struct.unpack(
             f"32s16s",
             serialized_message)

        recipient_ephemeral_public_key = X25519PublicKey.from_public_bytes(recipient_ephemeral_public_key_bytes)

        return RecipientHello(
            recipient_ephemeral_public_key,
            recipient_random_data)

"""
Represents the untagged part of the "sender hello" message.
See Notes/ABI/Peer Handshake.txt
"""
class PeerEnvelope:
    def __init__(
        self,
        wrapped_message: str):

        
        self.wrapped_message = wrapped_message

    """
    Formats the message information into an array of bytes and encrypts it
    as described in Notes/ABI/Peer Handshake.txt

    The peer connection is one-way, so there is only one send-key
    """
    def encrypt_and_serialize(
        self,
        send_key: ChaCha20Poly1305)->Union[bytes,bytearray]:

        if not isinstance(send_key,ChaCha20Poly1305):
            raise ValueError(
            f'send_key has type {type(send_key).__name__}.'+
            'should be ChaCha20Poly1305')


        nonce = os.urandom(struct.calcsize(_NONCE_FORMAT))
        encrypted_message =  send_key.encrypt(self, nonce, self.wrapped_message)
        messageLen = len(self.wrapped_message)

        serialized_encrypted_message = struct.pack(
            f"{_NONCE_FORMAT}{messageLen}s",
            encrypted_message)

        return serialized_encrypted_message

    """
    Accepts and decrypts a message which is formatted as an array of bytes,
    then parses it into a python object as described in
    Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sent the message, and the
    client-send key is used when the client sent the message.
    """
    @staticmethod
    def decrypt_and_deserialize(
        serialized_message: Union[bytes,bytearray],
        send_key: ChaCha20Poly1305)->PeerEnvelope:

        nonceLen = struct.calcsize(_NONCE_FORMAT)
        messageLen = len(serialized_message) - nonceLen
        unpacked_data = struct.unpack(f"{_NONCE_FORMAT}{messageLen}s",serialized_message)

        nonce = unpacked_data[0]
        ciphertext = unpacked_data[1]

        
        wrapped_message = send_key.decrypt(nonce,ciphertext)

        return PeerEnvelope(wrapped_message)