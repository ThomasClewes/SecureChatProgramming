from . import packets
from .packets import *
from ._client_state_machine import *
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

from . import _client_tests as self_module

def test_all():
    print('Running client tests')
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

def test_open_connection():
    handshake = ClientStateMachine()

    call_flag = False

    def test_packet(type,serialized_packet):
        nonlocal call_flag
        call_flag = True

        assert type == PACKETS["CLIENT_HELLO"],\
            f"Expected CLIENT_HELLO, found {INV_PACKETS.get(type,'INVALID')}"

        client_hello = ClientHello.deserialize(serialized_packet)

        original_random_bytes = handshake.client_random
        original_key_bytes = _format_x25519_public(
            handshake.client_ephemeral_public_key)

        received_random_bytes = client_hello.client_random
        received_key_bytes = _format_x25519_public(
            client_hello.client_ephemeral_public_key)

        assert \
            original_random_bytes == received_random_bytes, \
            "Client random was not recovered after deserialization:\n\t" \
            + f"original: {original_random_bytes}\n\t" \
            + f"received: {received_random_bytes}"

        assert \
            original_key_bytes == received_key_bytes, \
            "Client random was not recovered after deserialization:\n\t" \
            + f"original: {original_key_bytes}\n\t" \
            + f"received: {received_key_bytes}"

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_packet_send.add_handler(test_packet)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.start_connection()

    assert call_flag, "Client Authenticate Not Sent"

def test_receive_server_hello():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    username = "bob"
    signature = ca_private_key.sign(
        (username + '\n').encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256())

    handshake = ClientStateMachine()
    handshake._generate_parameters()
    handshake._main_state = "WAITING_FOR_HELLO"

    #handshake will not sent client_authenticate otherwise
    handshake.set_username(username, signature)

    server_random = os.urandom(packets.handshake_module.RANDOM_LENGTH)
    server_ephemeral_private_key = X25519PrivateKey.generate()
    server_ephemeral_public_key = server_ephemeral_private_key.public_key()
    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)
    server_persistent_public_key = server_persistent_private_key.public_key()

    premaster_key = server_ephemeral_private_key.exchange(
        handshake.client_ephemeral_public_key)

    master_key = (HKDF(
        algorithm = hashes.SHA256(),
        length = handshake_module.MASTER_KEY_LENGTH,
        salt = handshake.client_random + server_random,
        info = None)
        .derive(premaster_key))

    client_send_key_bytes = master_key[0:packets.crypt.CHACHA20_KEY_LENGTH]
    server_send_key_bytes = master_key[packets.crypt.CHACHA20_KEY_LENGTH:]

    server_hello = ServerHello(
        server_ephemeral_public_key,
        server_persistent_public_key,
        server_random,
        handshake.client_random)

    serialized_server_hello = server_hello.sign_and_serialize(
        server_persistent_private_key)

    call_flag = False

    def test_authenticate(message_tag,serialized_message):
        nonlocal call_flag
        call_flag = True

        assert message_tag == PACKETS["CLIENT_AUTHENTICATE"],\
            f"Expected CLIENT_AUTHENTICATE, found {INV_PACKETS.get(type,'INVALID')}"

        #Ensure values from sender_hello are incorporated
        assert handshake.server_random == server_random
        assert (
            _format_x25519_public(
                handshake.server_ephemeral_public_key)
             == _format_x25519_public(
                server_ephemeral_public_key))

        #Ensure keys are derived correctly
        assert handshake._client_send_key_bytes == client_send_key_bytes,\
            (
                f"Expected: {client_send_key_bytes}\n"
                +f"Actual: {handshake._client_send_key_bytes}"
            )
        assert handshake._server_send_key_bytes == server_send_key_bytes

        #ensure CLIENT_AUTHENTICATE deserializes correctly

        client_authenticate = ClientAuthenticate.decrypt_deserialize_and_validate(
            serialized_message,
            ChaCha20Poly1305(client_send_key_bytes),
            ca_public_key)

        assert client_authenticate.username == username
        assert client_authenticate.signature == signature

    def test_disconnect():
        assert False, "Should not have closed"

    def test_upstream_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_packet_send.add_handler(test_authenticate)
    handshake.on_disconnect.add_handler(test_disconnect)

    handshake.on_private_packet_received.add_handler(test_upstream_private_packet)
    handshake.on_broadcast_received.add_handler(test_upstream_broadcast)

    handshake.handle_packet(
        PACKETS["SERVER_HELLO"],
        serialized_server_hello)

    assert call_flag, "Client Authenticate Not Sent"

def test_receive_server_envelope():
    server_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    handshake = ClientStateMachine()
    handshake.server_send_key = server_send_key
    handshake._main_state = "RECEIVE_ONLY"

    expected_sender = "alice"
    expected_message = "hello".encode('utf-8')

    server_envelope = ServerEnvelope(
        expected_sender,
        expected_message)

    serialized_message = server_envelope.encrypt_and_serialize(
        server_send_key)

    call_flag = False

    def test_client(actual_sender,actual_message):
        nonlocal call_flag
        call_flag = True

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

    def test_upstream_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_private_packet_received.add_handler(
        test_client)
    handshake.on_disconnect.add_handler(
        test_disconnect)

    handshake.on_broadcast_received.add_handler(
        test_upstream_broadcast)

    handshake.handle_packet(
        PACKETS["SERVER_ENVELOPE"],
        serialized_message)

    assert call_flag

def test_send_private():
    client_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    handshake = ClientStateMachine()
    handshake.client_send_key = client_send_key
    handshake._main_state = "READY"

    expected_recipient = "alice"
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
            handshake.client_send_key
        )

        actual_recipient = server_envelope.username
        actual_packet = server_envelope.private_packet

        assert expected_recipient == actual_recipient,\
        (
            f"expected: {expected_recipient}\n"
            +f"actual: {actual_recipient}"
        )
        assert expected_packet == actual_packet,\
        (
            f"expected: {expected_packet}\n"
            +f"actual: {actual_packet}"
        )

    def test_disconnect():
        assert False, "Should not have closed"

    def test_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    def test_broadcast(*args):
        assert False, "Should not have sent broadcast packet to client"

    handshake.on_packet_send.add_handler(
        test_server_envelope)
    handshake.on_disconnect.add_handler(
        test_disconnect)

    handshake.on_private_packet_received.add_handler(
        test_private_packet)
    handshake.on_broadcast_received.add_handler(
        test_broadcast)

    handshake.send_private_packet(
        expected_recipient,
        expected_packet)

    assert call_flag

def test_client_handshake_receive_server_broadcast():
    server_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    handshake = ClientStateMachine()
    handshake.server_send_key = server_send_key
    handshake._main_state = "RECEIVE_ONLY"

    expected_sender = "alice"
    expected_message = "hello"

    broadcast = DistributeBroadcast(
        expected_sender,
        expected_message)

    serialized_message = broadcast.encrypt_and_serialize(
        server_send_key)

    call_flag = False

    def test_broadcast(actual_sender,actual_message):
        nonlocal call_flag
        call_flag = True

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

    def test_private_packet(*args):
        assert False, "Should not have sent private packet to client"

    handshake.on_packet_send.add_handler(
        test_broadcast)
    handshake.on_disconnect.add_handler(
        test_disconnect)

    handshake.on_broadcast_received.add_handler(
        test_broadcast)

    handshake.on_private_packet_received.add_handler(
        test_private_packet)

    handshake.handle_packet(
        PACKETS["DISTRIBUTE_SERVER_BROADCAST"],
        serialized_message)

    assert call_flag

def test_client_handshake_send_broadcast():
    server_send_key = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())

    handshake = ClientStateMachine()
    handshake.client_send_key = server_send_key
    handshake._main_state = "READY"

    expected_message = "hello"

    call_flag = False

    def test_client(message_tag,serialized_message):
        nonlocal call_flag
        call_flag = True

        assert message_tag == PACKETS["SEND_SERVER_BROADCAST"],\
            (
                "Expected: DISTRIBUTE_SERVER_BROADCAST\n"
                +f"actual: {INV_PACKETS.get(message_tag,'INVALID')}"
            )

        server_broadcast = SendBroadcast.decrypt_and_deserialize(
            serialized_message,
            handshake.client_send_key
        )

        actual_message = server_broadcast.message

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

    handshake.on_packet_send.add_handler(
        test_client)
    handshake.on_disconnect.add_handler(
        test_disconnect)

    handshake.on_broadcast_received.add_handler(
        test_upstream_private_packet)
    handshake.on_private_packet_received.add_handler(
        test_upstream_broadcast)

    handshake.send_broadcast(
        expected_message)

    assert call_flag
