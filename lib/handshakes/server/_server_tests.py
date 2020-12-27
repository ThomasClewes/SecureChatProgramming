from . import packets
from .packets import *
from ._server_state_machine import *
from lib.protocol import PACKETS
#can't do import lib.handshakes as handshake followed by handshakes.server
import lib.handshakes.server as handshake_module
import lib.crypt as crypt

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from base64 import b64encode
import os

from . import _server_tests as self_module

def test_all():
    print('Running server tests')
    for name, value in self_module.__dict__.items():
        if (
            callable(value)
            and name.startswith("test_")
            and not name == "test_all"
        ):
            print("\tRunning ",name)
            value()
            print("\tPass")

def _format_x25519_public(key):
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw)

def test_receive_client_hello():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    client_random = os.urandom(handshake_module.RANDOM_LENGTH)
    client_ephemeral_private_key = X25519PrivateKey.generate()
    client_ephemeral_public_key = client_ephemeral_private_key.public_key()

    client_hello = ClientHello(
        client_ephemeral_public_key,
        client_random)

    serialized_client_hello = client_hello.serialize()

    call_flag = False

    def test_hello(type,serialized_packet):
        nonlocal call_flag
        call_flag = True

        assert type == PACKETS["SERVER_HELLO"],\
            f"Expected CLIENT_HELLO, found {INV_PACKETS.get(type,'INVALID')}"

        #Ensure values from client hello are incorporated
        assert handshake.client_random == client_random

        assert (
            _format_x25519_public(
                handshake.client_ephemeral_public_key)
             == _format_x25519_public(
                client_ephemeral_public_key))

        #ensure server hello is serialized and signed correctly
        server_hello = ServerHello.validate_and_deserialize(
            serialized_packet,
            client_random)

        original_server_random_bytes = handshake.server_random
        original_client_random_bytes = client_random
        original_key_bytes = _format_x25519_public(
            handshake.server_ephemeral_public_key)

        received_client_random_bytes = server_hello.client_random
        received_server_random_bytes = server_hello.server_random
        received_key_bytes = _format_x25519_public(
            server_hello.server_ephemeral_public_key)

        assert \
            original_server_random_bytes == received_server_random_bytes, \
            "Server random was not recovered after deserialization:\n\t" \
            + f"original: {original_server_random_bytes}\n\t" \
            + f"received: {received_server_random_bytes}"

        assert \
            original_client_random_bytes == received_client_random_bytes, \
            "Client random was not recovered after deserialization:\n\t" \
            + f"original: {original_client_random_bytes}\n\t" \
            + f"received: {received_client_random_bytes}"

        assert \
            original_key_bytes == received_key_bytes, \
            "Server persistent public key was not recovered after deserialization:\n\t" \
            + f"original: {original_key_bytes}\n\t" \
            + f"received: {received_key_bytes}"

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to server"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to server"

    handshake.on_packet_send.add_handler(test_hello)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.handle_packet(
        PACKETS["CLIENT_HELLO"],
        serialized_client_hello)

    assert call_flag, "Server Hello Not Sent"

    #opposite side of the key exchange from what the tested handshake
    #will perform
    premaster_key = client_ephemeral_private_key.exchange(
        handshake.server_ephemeral_public_key)

    master_key = (HKDF(
        algorithm = hashes.SHA256(),
        length = handshake_module.MASTER_KEY_LENGTH,
        salt = client_random + handshake.server_random,
        info = None)
        .derive(premaster_key))

    client_send_key_bytes = master_key[0:packets.crypt.CHACHA20_KEY_LENGTH]
    server_send_key_bytes = master_key[packets.crypt.CHACHA20_KEY_LENGTH:]

    #Ensure keys are derived correctly
    assert handshake._client_send_key_bytes == client_send_key_bytes,\
        (
            f"Expected: {client_send_key_bytes}\n"
            +f"Actual: {handshake._client_send_key_bytes}"
        )
    assert handshake._server_send_key_bytes == server_send_key_bytes

def test_receive_client_authenticate():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    client_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    handshake.client_send_key = client_send_key
    handshake._state = "WAITING_FOR_AUTHENTICATE"

    expected_username = "bob"
    signature = ca_private_key.sign(
        (expected_username + '\n').encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256())

    client_authenticate = ClientAuthenticate(
        expected_username,
        signature)

    serialized_packet = client_authenticate.encrypt_and_serialize(
        client_send_key)

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to server"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to server"

    def test_downstream_packet(*args):
        assert False, "Should not have sent a packet to client"

    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_packet_send.add_handler(test_downstream_packet)
    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.handle_packet(
        PACKETS["CLIENT_AUTHENTICATE"],
        serialized_packet)

    assert handshake.username == expected_username

def test_receive_server_envelope():
    client_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    handshake.username = "bob"
    handshake.client_send_key = client_send_key
    handshake._state = "READY"

    expected_recipient = "alice"
    expected_message = "hello".encode('utf-8')

    server_envelope = ServerEnvelope(
        expected_recipient,
        expected_message)

    serialized_message = server_envelope.encrypt_and_serialize(
        client_send_key)

    call_flag = False

    def test_server(actual_sender, actual_recipient,actual_message):
        nonlocal call_flag
        call_flag = True

        assert handshake.username == actual_sender,\
        (
            f"expected: {username}\n"
            +f"actual: {actual_sender}"
        )

        assert expected_recipient == actual_recipient,\
        (
            f"expected: {expected_recipient}\n"
            +f"actual: {actual_recipient}"
        )

        assert expected_message == actual_message,\
        (
            f"expected: {expected_message}\n"
            +f"actual: {actual_message}"
        )

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_private_packet_received.add_handler(test_server)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.handle_packet(
        PACKETS["SERVER_ENVELOPE"],
        serialized_message)

    assert call_flag

def test_send_private():
    server_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    handshake.username = "bob"
    handshake.server_send_key = server_send_key
    handshake._state = "READY"

    expected_sender = "alice"
    expected_packet = "hello".encode('utf-8')

    call_flag = False

    def test_server_envelope(message_tag,serialized_message):
        nonlocal call_flag
        call_flag = True

        assert message_tag == PACKETS["SERVER_ENVELOPE"],\
            (
                "Expected: SERVER_ENVELOPE\n"
                +f"actual: {INV_PACKETS.get(message_tag,'INVALID')}"
            )

        server_envelope = ServerEnvelope.decrypt_and_deserialize(
            serialized_message,
            server_send_key
        )

        actual_sender = server_envelope.username
        actual_packet = server_envelope.private_packet

        assert expected_sender == actual_sender,\
        (
            f"expected: {expected_sender}\n"
            +f"actual: {actual_sender}"
        )
        assert expected_packet == actual_packet,\
        (
            f"expected: {expected_packet}\n"
            +f"actual: {actual_packet}"
        )

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_packet_send.add_handler(test_server_envelope)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.send_private_packet(
        expected_sender,
        expected_packet)

    assert call_flag

def test_receive_server_broadcast():
    client_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    handshake.username = "bob"
    handshake.client_send_key = client_send_key
    handshake._state = "READY"

    expected_message = "hello"

    broadcast = SendBroadcast(
        expected_message)

    serialized_message = broadcast.encrypt_and_serialize(
        client_send_key)

    call_flag = False

    def test_client(actual_sender,actual_message):
        nonlocal call_flag
        call_flag = True

        assert expected_message == actual_message,\
        (
            f"expected: {expected_message}\n"
            +f"actual: {actual_message}"
        )

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    handshake.on_broadcast_received.add_handler(test_client)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)

    handshake.handle_packet(
        PACKETS["SEND_SERVER_BROADCAST"],
        serialized_message)

    assert call_flag

def test_distribute_broadcast():
    server_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    handshake.username = "bob"
    handshake.server_send_key = server_send_key
    handshake._state = "READY"

    expected_sender = 'alice'
    expected_message = "hello"

    call_flag = False

    def test_client(message_tag,serialized_message):
        nonlocal call_flag
        call_flag = True

        assert message_tag == PACKETS["DISTRIBUTE_SERVER_BROADCAST"],\
            (
                "Expected: DISTRIBUTE_SERVER_BROADCAST\n"
                +f"actual: {INV_PACKETS.get(message_tag,'INVALID')}"
            )

        server_broadcast = DistributeBroadcast.decrypt_and_deserialize(
            serialized_message,
            server_send_key
        )

        actual_sender = server_broadcast.sender_username
        actual_message = server_broadcast.message

        assert expected_sender == actual_sender,\
        (
            f"expected: {expected_sender}\n"
            +f"actual: {actual_sender}"
        )

        assert expected_message == actual_message,\
        (
            f"expected: {expected_message}\n"
            +f"actual: {actual_message}"
        )

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_packet_send.add_handler(test_client)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.send_broadcast(
        expected_sender,
        expected_message)

    assert call_flag
