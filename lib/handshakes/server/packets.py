from __future__ import annotations

import lib.handshakes.server as handshake_module
import lib.crypt as crypt

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import constant_time

import struct
import os
from typing import Union

#in a class and using functions to break circular references
class _Formats:
        @staticmethod
        def random_format():
            return f"{handshake_module.RANDOM_LENGTH}s"

        @staticmethod
        def nonce_format():
            return f"{crypt.CHACHA20_NONCE_LENGTH}s"

        @staticmethod
        def x25519_key_format():
            return f"{crypt.X25519_KEY_LENGTH}s"

        @staticmethod
        def rsa_signature_format():
            return f"{handshake_module.RSA_SIGNATURE_LENGTH}s"

        #this could be a "proper" constant, but it would be the only
        #proper constant in the class.
        @staticmethod
        def username_length_format():
            return "b"

        #These are probably the only reasonable formats for these types,
        #but they're functions just in case
        @staticmethod
        def unsized_username_format(username_bytes_length):
            return f"{username_bytes_length}s"

        #requires two parameters in struct.pack:
        #the size and then the bytes
        @staticmethod
        def sized_username_format(username_bytes_length):
            return f"B{username_bytes_length}s"

        @staticmethod
        def rsa_key_format(key_bytes_length):
            return f"{key_bytes_length}s"

        @staticmethod
        def private_packet_format(packet_length):
            return f"{packet_length}s"

"""
Represents the untagged part of the "client hello" message.
See Notes/ABI/Server Handshake.txt
"""
class ClientHello:
    def __init__(
        self,
        client_ephemeral_public_key: X25519PublicKey,
        client_random: Union[bytes,bytearray]):

        #hard type requirements for cryptographic primitives
        if not isinstance(client_ephemeral_public_key,X25519PublicKey):
            raise ValueError(
            f'client_ephemeral_public_key has type {type(client_ephemeral_public_key).__name__}.'+
            'should be X25519PublicKey')

        #enforce immutability to avoid accidentally smashing the caller's
        #buffers
        client_random = bytes(client_random)

        if len(client_random) != 16:
            raise ValueError(
                f'client_random has length {len(client_random)} bytes. '+
                'should be 16')

        self.client_ephemeral_public_key=client_ephemeral_public_key
        self.client_random=client_random

    """
    Formats the message information into an array of bytes as described in
    Notes/ABI/Server Handshake.txt
    """
    def serialize(self)->Union[bytes,bytearray]:
        #todo: use struct.pack
        client_ephemeral_public_key_bytes = self.client_ephemeral_public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        serialized_hello = struct.pack(
            f"{_Formats.x25519_key_format()}{_Formats.random_format()}",
            client_ephemeral_public_key_bytes,
            self.client_random)

        return serialized_hello

    """
    Accepts a message which is formatted as an array of bytes and parses it into
    a python object as described in Notes/ABI/Server Handshake.txt
    """

    @staticmethod
    def deserialize(serialized_hello: Union[bytes,bytearray]) -> ClientHello:
        #enforce immutability to avoid accidentally smashing the caller's
        #buffers
        serialized_hello = bytes(serialized_hello)

        #todo: use struct.unpack

        client_ephemeral_public_key_bytes, client_random = struct.unpack(
            f"{_Formats.x25519_key_format()}{_Formats.random_format()}",
            serialized_hello
        )

        client_ephemeral_public_key = X25519PublicKey.from_public_bytes(
            client_ephemeral_public_key_bytes)

        return ClientHello(client_ephemeral_public_key,client_random)

"""
Represents the untagged part of the "server hello" message.
See Notes/ABI/Server Handshake.txt
"""
class ServerHello:

    def __init__(
        self,
        server_ephemeral_public_key: X25519PublicKey,
        server_persistent_public_key:RSAPublicKey,
        server_random: Union[bytes,bytearray],
        client_random: Union[bytes,bytearray]):

        #hard type requirements for cryptographic primitives
        if not isinstance(server_ephemeral_public_key,(X25519PublicKey)):
            raise ValueError(
            f'server_ephemeral_public_key has type {type(server_ephemeral_public_key).__name__}.'+
            'should be X25519PublicKey')

        if not isinstance(server_persistent_public_key,(RSAPublicKey)):
            raise ValueError(
            f'server_persistent_public_key has type {type(server_persistent_public_key).__name__}.'+
            'should be RSAPublicKey')

        #enforce immutability to avoid accidentally smashing the caller's
        #buffers
        server_random = bytes(server_random)
        client_random = bytes(client_random)

        if len(server_random) != struct.calcsize(_Formats.random_format()):
            raise ValueError(
                f'server_random has length {len(server_random)} bytes. '+
                'should be 16')

        if len(client_random) != 16:
            raise ValueError(
                f'client_random has length {len(client_random)} bytes. '+
                'should be 16')

        self.server_ephemeral_public_key = server_ephemeral_public_key
        self.server_persistent_public_key = server_persistent_public_key
        self.server_random = server_random
        self.client_random = client_random

    """
    Signs the message and formats the message information and signature
    into an array of bytes as described in
    Notes/ABI/Server Handshake.txt
    """
    def sign_and_serialize(
        self,
        server_persistent_private_key: RSAPrivateKey)->Union[bytes,bytearray]:

        #hard type requirements for cryptographic primitives
        if not isinstance(server_persistent_private_key,(RSAPrivateKey)):
            raise ValueError(
            f'server_persistent_private_key has type {type(server_persistent_private_key).__name__}.'+
            'should be RSAPrivateKey')

        server_ephemeral_public_key_bytes = (self.server_ephemeral_public_key
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw))
        server_persistent_public_key_bytes = (self.server_persistent_public_key
            .public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1))

        server_persistent_public_key_bytes_length = len(server_persistent_public_key_bytes)

        unverified_packet = struct.pack(
            (
                f"{_Formats.x25519_key_format()}"
                +f"{_Formats.random_format()}"
                +f"{_Formats.random_format()}"
                +f"{_Formats.rsa_key_format(server_persistent_public_key_bytes_length)}"
            ),
            server_ephemeral_public_key_bytes,
            self.server_random,
            self.client_random,
            server_persistent_public_key_bytes)

        unverified_packet_length = len(unverified_packet)

        signature = server_persistent_private_key.sign(
            unverified_packet,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())

        return struct.pack(
            f"{_Formats.rsa_signature_format()}{unverified_packet_length}s",
            signature,
            unverified_packet)

    """
    Accepts a signed message which is formatted as an array of bytes,
    verifies the signature, and parses the message into a python object
    as described in Notes/ABI/Server Handshake.txt
    """

    #added static method to remove the inputs warning
    @staticmethod
    def validate_and_deserialize(
        serialized_hello: Union[bytes,bytearray],
        correct_client_random: Union[bytes,bytearray]) -> ServerHello:

        #enforce immutability to avoide accidentally smashing the caller's
        #buffers
        correct_client_random = bytes(correct_client_random)
        serialized_hello = bytes(serialized_hello)

        if len(correct_client_random) != 16:
            raise ValueError(
                f'correct_client_random has length {len(correct_client_random)} bytes. '+
                'should be 16')

        unverified_hello_length = (
            len(serialized_hello)
            - struct.calcsize(_Formats.rsa_signature_format()))

        signature, unverified_hello = struct.unpack(
            f"{_Formats.rsa_signature_format()}{unverified_hello_length}s",
            serialized_hello)

        server_persistent_public_key_length = (
            len(unverified_hello)
            -struct.calcsize(_Formats.x25519_key_format())
            #server random
            -struct.calcsize(_Formats.random_format())
            #client random
            -struct.calcsize(_Formats.random_format()))

        (
            server_ephemeral_public_key_bytes,
            server_random,
            client_random,
            server_persistent_public_key_bytes
        ) = struct.unpack(
            (
                f"{_Formats.x25519_key_format()}"
                +f"{_Formats.random_format()}"
                +f"{_Formats.random_format()}"
                +f"{_Formats.rsa_key_format(server_persistent_public_key_length)}"
            ),
            unverified_hello)

        server_ephemeral_public_key = X25519PublicKey.from_public_bytes(
            server_ephemeral_public_key_bytes)
        server_persistent_public_key = serialization.load_der_public_key(
            server_persistent_public_key_bytes)

        if not isinstance(server_persistent_public_key, RSAPublicKey):
            raise ValueError(
                'message public key was not an RSAPublicKey. '+
                f'It was {type(server_persistent_public_key).__name__}')

        #This verification is a bit bogus since the client has no way to verify whether
        #the public key is correct
        server_persistent_public_key.verify(
            signature,
            unverified_hello,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())

        if not constant_time.bytes_eq(correct_client_random,client_random):
            raise ValueError(
                'message did not have correct client random')

        return ServerHello(
            server_ephemeral_public_key,
            server_persistent_public_key,
            server_random,
            client_random)

"""
Represents the untagged part of the "client authenticate" message.
See Notes/ABI/Server Handshake.txt
"""
class ClientAuthenticate:
    def __init__(
        self,
        username: str,
        signature: Union[bytes,bytearray]):
        #enforce immutability to avoide accidentally smashing the caller's
        #buffers
        signature = bytes(signature)

        if len(signature)!=256:
            raise ValueError(
                f'signature has length {len(signature)} bytes. '+
                'should be 256')

        self.signature = signature
        self.username = str(username)

    """
    Formats the message information into an array of bytes and encrypts it
    as described in Notes/ABI/Server Handshake.txt
    """
    def encrypt_and_serialize(
        self,
        client_send_key: ChaCha20Poly1305) ->  Union[bytes,bytearray]:

        #hard type requirements for cryptographic primitives
        if not isinstance(client_send_key,ChaCha20Poly1305):
            raise ValueError(
            f'client_send_key has type {type(client_send_key).__name__}.'+
            'should be ChaCha20Poly1305')

        username_bytes = self.username.encode('utf-8')

        plaintext = struct.pack(
            (
                f"{_Formats.rsa_signature_format()}"
                +f"{_Formats.unsized_username_format(len(self.username))}"
            ),
            self.signature,
            self.username.encode('utf-8'))

        nonce = os.urandom(struct.calcsize(_Formats.nonce_format()))

        ciphertext =  client_send_key.encrypt(nonce, plaintext,None)

        #serializes the encryped message
        serialized_packet = struct.pack(
            f"{_Formats.nonce_format()}{len(ciphertext)}s",
            nonce,
            ciphertext)

        return serialized_packet

    """
    Accepts and decrypts a message which is formatted as an array of bytes,
    then parses it into a python object as described in
    Notes/ABI/Server Handshake.txt
    """

    #added static method to remove the inputs warning
    @staticmethod
    def decrypt_deserialize_and_validate(
        serialized_packet: Union[bytes,bytearray],
        client_send_key: ChaCha20Poly1305,
        verification_key: RSAPublicKey)->ClientAuthenticate:

        packet_length = (
            len(serialized_packet)
            - struct.calcsize(_Formats.nonce_format()))

        nonce, ciphertext = struct.unpack(
            f"{_Formats.nonce_format()}{packet_length}s",
            serialized_packet)

        plaintext = client_send_key.decrypt(nonce,ciphertext,None)

        username_bytes_length = (
            len(plaintext)
            -struct.calcsize(
                _Formats.rsa_signature_format()))

        signature, username_bytes = struct.unpack(
            f"{_Formats.rsa_signature_format()}{username_bytes_length}s",
            plaintext)

        verification_key.verify(
            signature,
            username_bytes + '\n'.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256())

        username = username_bytes.decode('utf-8')

        return ClientAuthenticate(username,signature)


"""
Represents the untagged part of the "server envelope" message.
See Notes/ABI/Server Handshake.txt
"""
class ServerEnvelope:
    def __init__(
        self,
        username:str,
        private_packet: Union[bytes,bytearray]):

        self.username = username
        self.private_packet = bytes(private_packet)

    """
    Formats the message information into an array of bytes and encrypts it
    as described in Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sends the message, and the
    client-send key is used when the client sends the message.
    """
    def encrypt_and_serialize(
        self,
        send_key: ChaCha20Poly1305)->Union[bytes,bytearray]:

        #hard type requirements for cryptographic primitives
        if not isinstance(send_key,ChaCha20Poly1305):
            raise ValueError(
            f'send_key has type {type(send_key).__name__}.'+
            'should be ChaCha20Poly1305')

        username_bytes = self.username.encode('utf-8')

        plaintext = struct.pack(
            (
                f"{_Formats.sized_username_format(len(username_bytes))}"
                +f"{len(self.private_packet)}s"
            ),
            len(username_bytes),
            username_bytes,
            self.private_packet)

        nonce = os.urandom(struct.calcsize(_Formats.nonce_format()))

        ciphertext = send_key.encrypt(
            nonce,
            plaintext,
            None)

        #serializes the encryped message
        serialized_envelope = struct.pack(
            f"{_Formats.nonce_format()}{len(ciphertext)}s",
            nonce,
            ciphertext)

        return serialized_envelope

    """
    Accepts and decrypts a message which is formatted as an array of bytes,
    then parses it into a python object as described in
    Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sent the message, and the
    client-send key is used when the client sent the message.
    """
    @staticmethod
    def decrypt_and_deserialize(
        serialized_envelope: Union[bytes,bytearray],
        send_key: ChaCha20Poly1305)->ServerEnvelope:

        ciphertext_length = len(serialized_envelope) - struct.calcsize(_Formats.nonce_format())
        nonce, ciphertext = struct.unpack(
            f"{_Formats.nonce_format()}{ciphertext_length}s",
            serialized_envelope)


        plaintext = send_key.decrypt(nonce,ciphertext,None)

        username_bytes_length, *_ = struct.unpack_from(
            _Formats.username_length_format(),
            plaintext,
            0)
        private_packet_length = (
            len(plaintext)
            -username_bytes_length
            -struct.calcsize(_Formats.username_length_format()))

        username_bytes, private_packet = struct.unpack(
            (
                f"{_Formats.unsized_username_format(username_bytes_length)}"
                +f"{private_packet_length}s"
            ),
            plaintext[struct.calcsize(_Formats.username_length_format()):])

        return ServerEnvelope(
            username_bytes.decode('utf-8'),
            private_packet)

"""
Represents the untagged part of the "send broadcast" message.
See Notes/ABI/Server Handshake.txt
"""
class SendBroadcast:
    def __init__(
        self,
        message: str):

        self.message = message

    """
    Formats the message information into an array of bytes and encrypts it
    as described in Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sends the message, and the
    client-send key is used when the client sends the message.
    """
    def encrypt_and_serialize(
        self,
        client_send_key: ChaCha20Poly1305)->Union[bytes,bytearray]:

        #hard type requirements for cryptographic primitives
        if not isinstance(client_send_key,ChaCha20Poly1305):
            raise ValueError(
            f'client_send_key has type {type(client_send_key).__name__}.'+
            'should be ChaCha20Poly1305')

        message_bytes = self.message.encode('utf-8')

        nonce = os.urandom(struct.calcsize(_Formats.nonce_format()))

        ciphertext =  client_send_key.encrypt(nonce, message_bytes,None)

        #gets byte length of message
        ciphertext_length = len(ciphertext)

        #serializes the encryped message
        serialized_broadcast = struct.pack(
            f"{_Formats.nonce_format()}{ciphertext_length}s",
            nonce,
            ciphertext)

        return serialized_broadcast

    """
    Accepts and decrypts a message which is formatted as an array of bytes,
    then parses it into a python object as described in
    Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sent the message, and the
    client-send key is used when the client sent the message.
    """

    #added static method to remove the inputs warning
    @staticmethod
    def decrypt_and_deserialize(
        serialized_broadcast: Union[bytes,bytearray],
        client_send_key: ChaCha20Poly1305)->SendBroadcast:

        ciphertext_length = len(serialized_broadcast) - struct.calcsize(_Formats.nonce_format())
        nonce, ciphertext = struct.unpack(
            f"{_Formats.nonce_format()}{ciphertext_length}s",
            serialized_broadcast)

        message_bytes = client_send_key.decrypt(nonce,ciphertext,None)

        return SendBroadcast(message_bytes.decode('utf-8'))

"""
Represents the untagged part of the "distribute broadcast" message.
See Notes/ABI/Server Handshake.txt
"""
class DistributeBroadcast:
    def __init__(
        self,
        sender_username:str,
        message: str):

        self.sender_username = sender_username
        self.message = message

    """
    Formats the message information into an array of bytes and encrypts it
    as described in Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sends the message, and the
    client-send key is used when the client sends the message.
    """

    #moved the pointer output to the same line,
    #throws an error when on seperate lines in my IDE
    def encrypt_and_serialize(
        self,
        server_send_key: ChaCha20Poly1305)->Union[bytes,bytearray]:

        #hard type requirements for cryptographic primitives
        if not isinstance(server_send_key,ChaCha20Poly1305):
            raise ValueError(
            f'server_send_key has type {type(server_send_key).__name__}.'+
            'should be ChaCha20Poly1305')

        username_bytes = self.sender_username.encode('utf-8')
        username_bytes_length = len(username_bytes)

        message_bytes = self.message.encode('utf-8')
        message_bytes_length = len(message_bytes)

        plaintext = struct.pack(
            (
                f"{_Formats.sized_username_format(username_bytes_length)}"
                +f"{message_bytes_length}s"
            ),
            username_bytes_length,
            username_bytes,
            message_bytes)

        nonce = os.urandom(struct.calcsize(_Formats.nonce_format()))

        ciphertext = server_send_key.encrypt(
            nonce,
            plaintext,
            None)

        ciphertext_length = len(ciphertext)

        serialized_broadcast = struct.pack(
            f"{_Formats.nonce_format()}{ciphertext_length}s",
            nonce,
            ciphertext)

        return serialized_broadcast

    """
    Accepts and decrypts a message which is formatted as an array of bytes,
    then parses it into a python object as described in
    Notes/ABI/Server Handshake.txt

    The server-send key is used when the server sent the message, and the
    client-send key is used when the client sent the message.
    """

    #added static method to remove the inputs warning
    @staticmethod
    def decrypt_and_deserialize(
        serialized_broadcast: Union[bytes,bytearray],
        server_send_key: ChaCha20Poly1305)->DistributeBroadcast:

        ciphertext_length = len(serialized_broadcast) - struct.calcsize(_Formats.nonce_format())
        nonce, ciphertext = struct.unpack(
            f"{_Formats.nonce_format()}{ciphertext_length}s",
            serialized_broadcast)

        plaintext = server_send_key.decrypt(nonce,ciphertext,None)
        username_bytes_length, *_ = struct.unpack_from(
            _Formats.username_length_format(),
            plaintext,
            0)

        message_bytes_length = (
            len(plaintext)
            -username_bytes_length
            -struct.calcsize(_Formats.username_length_format())
        )

        username_bytes, message_bytes = struct.unpack(
            (
                f"{_Formats.unsized_username_format(username_bytes_length)}"
                +f"{message_bytes_length}s"
            ),
            plaintext[struct.calcsize(_Formats.username_length_format()):])

        return DistributeBroadcast(
            username_bytes.decode('utf-8'),
            message_bytes.decode('utf-8'))
