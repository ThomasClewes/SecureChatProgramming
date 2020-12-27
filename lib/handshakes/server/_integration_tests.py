from . import packets
from .packets import *
from ._client_state_machine import *
from ._server_state_machine import *
from lib.protocol import PACKETS
from lib.connector import TrampolineConnector
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

from . import _integration_tests as self_module

def test_all():
    print('Running integration tests')
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

def test_connect():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    username = "bob"
    signature = ca_private_key.sign(
        (username + '\n').encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256())

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    server_handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    client_handshake = ClientStateMachine()

    #setup connection between handshakes

    client_side_trampoline = TrampolineConnector()
    server_side_trampoline = TrampolineConnector()

    def pass_to_client_trampoline(*packet_data):
        client_side_trampoline.send(*packet_data)
    def pass_to_server_trampoline(*packet_data):
        server_side_trampoline.send(*packet_data)


    client_handshake.on_packet_send.add_handler(pass_to_client_trampoline)
    server_handshake.on_packet_send.add_handler(pass_to_server_trampoline)

    def pass_to_server(*packet_data):
        server_handshake.handle_packet(
            *packet_data)

    def pass_to_client(*packet_data):
        client_handshake.handle_packet(
            *packet_data)

    def peek_from_client(packet_tag,*_):
        print("\t\tClient Sent ", INV_PACKETS[packet_tag])

    def peek_from_server(packet_tag,*_):
        print("\t\tServer Sent ", INV_PACKETS[packet_tag])

    server_side_trampoline.after_send.add_handler(
        pass_to_client)
    client_side_trampoline.after_send.add_handler(
        pass_to_server)

    server_side_trampoline.before_send.add_handler(
        peek_from_server)
    client_side_trampoline.before_send.add_handler(
        peek_from_client)

    def pump_with_limit(limit):
        nonlocal client_side_trampoline
        nonlocal server_side_trampoline

        pump_count = 0
        while pump_count < limit:
            if (
                not client_side_trampoline.pump()
                and not server_side_trampoline.pump()
            ):
                return True
            pump_count = pump_count + 1
        return False

    #auto-accept client_authenticate
    def accept_username(userame,signature):
        server_handshake.accept_username()

    server_handshake.on_username_requested.add_handler(
        accept_username)

    #unexpected events

    def test_server_disconnect():
        assert False, "Server should not have disconnected"

    def test_client_disconnect():
        assert False, "Client should not have disconnected"

    def test_server_upstream_private_packet(*args):
        assert False, "Client should not have sent private packet to server"

    def test_client_upstream_private_packet(*args):
        assert False, "Server should not have sent private packet to client"

    def test_server_upstream_broadcast(*args):
        assert False, "Client should not have sent broadcast packet to server"

    def test_client_upstream_broadcast(*args):
        assert False, "Server should not have sent broadcast packet to client"

    server_handshake.on_disconnect.add_handler(
        test_server_disconnect)
    client_handshake.on_disconnect.add_handler(
        test_client_disconnect)
    server_handshake.on_private_packet_received.add_handler(
        test_server_upstream_private_packet)
    client_handshake.on_private_packet_received.add_handler(
        test_client_upstream_private_packet)
    server_handshake.on_broadcast_received.add_handler(
        test_server_upstream_broadcast)
    client_handshake.on_broadcast_received.add_handler(
        test_client_upstream_broadcast)

    #execute test

    #implicitly starts connection
    client_handshake.set_username(username,signature)

    assert pump_with_limit(20), (
        "Too many messages sent")

    #expected outcomes

    assert client_handshake._main_state == "READY", (
        f"Actual State: {client_handshake._main_state}")
    assert client_handshake._username_state == "READY", (
        f"Actual State: {client_handshake._state}")
    assert server_handshake._state == "READY", (
        f"Actual State: {server_handshake._state}")

def test_server_queue():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    username = "bob"
    signature = ca_private_key.sign(
        (username + '\n').encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256())

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    server_handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    client_handshake = ClientStateMachine()

    #setup connection between handshakes

    client_side_trampoline = TrampolineConnector()
    server_side_trampoline = TrampolineConnector()

    def pass_to_client_trampoline(*packet_data):
        client_side_trampoline.send(*packet_data)
    def pass_to_server_trampoline(*packet_data):
        server_side_trampoline.send(*packet_data)


    client_handshake.on_packet_send.add_handler(pass_to_client_trampoline)
    server_handshake.on_packet_send.add_handler(pass_to_server_trampoline)

    def pass_to_server(*packet_data):
        server_handshake.handle_packet(
            *packet_data)

    def pass_to_client(*packet_data):
        client_handshake.handle_packet(
            *packet_data)

    def peek_from_client(packet_tag,*_):
        print("\t\tClient Sent ", INV_PACKETS[packet_tag])

    def peek_from_server(packet_tag,*_):
        print("\t\tServer Sent ", INV_PACKETS[packet_tag])

    server_side_trampoline.after_send.add_handler(
        pass_to_client)
    client_side_trampoline.after_send.add_handler(
        pass_to_server)

    server_side_trampoline.before_send.add_handler(
        peek_from_server)
    client_side_trampoline.before_send.add_handler(
        peek_from_client)

    def pump_with_limit(limit):
        nonlocal client_side_trampoline
        nonlocal server_side_trampoline

        pump_count = 0
        while pump_count < limit:
            if (
                not client_side_trampoline.pump()
                and not server_side_trampoline.pump()
            ):
                return True
            pump_count = pump_count + 1
        return False

    #unexpected events

    def test_server_disconnect():
        assert False, "Server should not have disconnected"

    def test_client_disconnect():
        assert False, "Client should not have disconnected"

    def test_server_upstream_private_packet(*args):
        assert False, "Client should not have sent private packet to server"

    def test_server_upstream_broadcast(*args):
        assert False, "Client should not have sent broadcast packet to server"

    server_handshake.on_disconnect.add_handler(
        test_server_disconnect)
    client_handshake.on_disconnect.add_handler(
        test_client_disconnect)
    server_handshake.on_disconnect.add_handler(
        test_server_upstream_private_packet)
    server_handshake.on_disconnect.add_handler(
        test_server_upstream_broadcast)

    #test data

    test_data = [
        ("BROADCAST","user1","message1"),
        ("PRIVATE","user2","message2".encode('utf-8')),
        ("BROADCAST","user2","message2"),
        ("BROADCAST","user3","message3"),
        ("PRIVATE","user1","message4".encode('utf-8')),
    ]

    for type, sender, message in test_data:
        if type == "BROADCAST":
            server_handshake.send_broadcast(
                sender,
                message)
        elif type == "PRIVATE":
            server_handshake.send_private_packet(
                sender,
                message)

    #expected events

    received_index = 0

    def test_broadcast(actual_sender, actual_packet):
        nonlocal received_index

        assert received_index < len(test_data), "To many messages given to client"

        expected_type, expected_sender, expected_packet = test_data[received_index]
        assert expected_type == "BROADCAST", (
            "Expected broadcast but got private message\n"
            +f"Message index: {received_index}")
        assert expected_sender == actual_sender, (
            "\n"
            +f"Expected: {expected_sender}\n"
            +f"Actual: {actual_sender}\n"
            +f"Message index: {received_index}\n")
        assert expected_packet == actual_packet, (
            "\n"
            +f"Expected: {expected_packet}\n"
            +f"Actual: {actual_packet}\n"
            +f"Message index: {received_index}")

        received_index = received_index+1

    def test_private(actual_sender, actual_packet):
        nonlocal received_index

        assert received_index < len(test_data), "To many messages given to client"

        expected_type, expected_sender, expected_packet = test_data[received_index]
        assert expected_type == "PRIVATE",  (
            "Expected private message but got broadcast\n"
            +f"Message index: {received_index}")
        assert expected_sender == actual_sender, (
            "\n"
            +f"Expected: {expected_sender}\n"
            +f"Actual: {actual_sender}\n"
            +f"Message index: {received_index}")
        assert expected_packet == actual_packet, (
            "\n"
            +f"Expected: {expected_packet}\n"
            +f"Actual: {actual_packet}\n"
            +f"Message index: {received_index}")

        received_index = received_index+1

    client_handshake.on_private_packet_received.add_handler(
        test_private)
    client_handshake.on_broadcast_received.add_handler(
        test_broadcast)

    #execute test

    client_handshake.start_connection()

    assert pump_with_limit(20), (
        "Too many messages sent")

    #expected outcomes
    assert client_handshake._main_state == "RECEIVE_ONLY", (
        f"Actual State: {client_handshake._main_state}")
    assert client_handshake._username_state == "NO_USERNAME", (
        f"Actual State: {client_handshake._username_state}")
    assert server_handshake._state == "WAITING_FOR_AUTHENTICATE", (
        f"Actual State: {server_handshake._state}")
    assert received_index == len(test_data), f"Messages Sent: {received_index}"

def test_client_queue():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    username = "bob"
    signature = ca_private_key.sign(
        (username + '\n').encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256())

    server_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)

    server_handshake = ServerStateMachine(
        server_persistent_private_key,
        ca_public_key)

    client_handshake = ClientStateMachine()

    #setup connection between handshakes

    client_side_trampoline = TrampolineConnector()
    server_side_trampoline = TrampolineConnector()

    def pass_to_client_trampoline(*packet_data):
        client_side_trampoline.send(*packet_data)
    def pass_to_server_trampoline(*packet_data):
        server_side_trampoline.send(*packet_data)


    client_handshake.on_packet_send.add_handler(pass_to_client_trampoline)
    server_handshake.on_packet_send.add_handler(pass_to_server_trampoline)

    def pass_to_server(*packet_data):
        server_handshake.handle_packet(
            *packet_data)

    def pass_to_client(*packet_data):
        client_handshake.handle_packet(
            *packet_data)

    def peek_from_client(packet_tag,*_):
        print("\t\tClient Sent ", INV_PACKETS[packet_tag])

    def peek_from_server(packet_tag,*_):
        print("\t\tServer Sent ", INV_PACKETS[packet_tag])

    server_side_trampoline.after_send.add_handler(
        pass_to_client)
    client_side_trampoline.after_send.add_handler(
        pass_to_server)

    server_side_trampoline.before_send.add_handler(
        peek_from_server)
    client_side_trampoline.before_send.add_handler(
        peek_from_client)

    def pump_with_limit(limit):
        nonlocal client_side_trampoline
        nonlocal server_side_trampoline

        pump_count = 0
        while pump_count < limit:
            if (
                not client_side_trampoline.pump()
                and not server_side_trampoline.pump()
            ):
                return True
            pump_count = pump_count + 1
        return False

    #auto-accept client_authenticate
    def accept_username(userame,signature):
        server_handshake.accept_username()

    server_handshake.on_username_requested.add_handler(
        accept_username)

    #unexpected events

    def test_server_disconnect():
        assert False, "Server should not have disconnected"

    def test_client_disconnect():
        assert False, "Client should not have disconnected"

    def test_client_upstream_private_packet(*args):
        assert False, "Server should not have sent private packet to client"

    def test_client_upstream_broadcast(*args):
        assert False, "Server should not have sent broadcast packet to client"

    server_handshake.on_disconnect.add_handler(
        test_server_disconnect)
    client_handshake.on_disconnect.add_handler(
        test_client_disconnect)
    client_handshake.on_private_packet_received.add_handler(
        test_client_upstream_private_packet)
    client_handshake.on_broadcast_received.add_handler(
        test_client_upstream_broadcast)

    #test data

    test_data = [
        ("BROADCAST",None,"message1"),
        ("PRIVATE","user2","message2".encode('utf-8')),
        ("BROADCAST",None,"message2"),
        ("BROADCAST",None,"message3"),
        ("PRIVATE","user1","message4".encode('utf-8')),
    ]

    #implicitly starts connection. Will still queue
    #since the trampolines are not being pumped
    for type, recipient, message in test_data:
        if type == "BROADCAST":
            client_handshake.send_broadcast(
                    message)
        elif type == "PRIVATE":
            client_handshake.send_private_packet(
                recipient,
                message)

    #expected events

    received_index = 0

    def test_broadcast(actual_sender, actual_packet):
        nonlocal received_index

        assert received_index < len(test_data), "To many messages given to client"

        expected_type, _, expected_packet = test_data[received_index]
        assert expected_type == "BROADCAST", (
            "Expected broadcast but got private message\n"
            +f"Message index: {received_index}")
        assert username == actual_sender, (
            "\n"
            +f"Expected: {expected_sender}\n"
            +f"Actual: {actual_sender}\n"
            +f"Message index: {received_index}\n")
        assert expected_packet == actual_packet, (
            "\n"
            +f"Expected: {expected_packet}\n"
            +f"Actual: {actual_packet}\n"
            +f"Message index: {received_index}")

        received_index = received_index+1

    def test_private(actual_sender, actual_recipient, actual_packet):
        nonlocal received_index

        assert received_index < len(test_data), "To many messages given to client"

        expected_type, expected_recipient, expected_packet = test_data[received_index]
        assert expected_type == "PRIVATE",  (
            "Expected private message but got broadcast\n"
            +f"Message index: {received_index}")
        assert expected_recipient == actual_recipient, (
            "\n"
            +f"Expected: {expected_recipient}\n"
            +f"Actual: {actual_recipient}\n"
            +f"Message index: {received_index}")
        assert username == actual_sender, (
            "\n"
            +f"Expected: {username}\n"
            +f"Actual: {actual_sender}\n"
            +f"Message index: {received_index}")
        assert expected_packet == actual_packet, (
            "\n"
            +f"Expected: {expected_packet}\n"
            +f"Actual: {actual_packet}\n"
            +f"Message index: {received_index}")

        received_index = received_index+1

    server_handshake.on_private_packet_received.add_handler(
        test_private)
    server_handshake.on_broadcast_received.add_handler(
        test_broadcast)

    #execute test

    #enables messages to be sent
    client_handshake.set_username(username,signature)

    assert pump_with_limit(20), (
        "Too many messages sent")

    #expected outcomes

    assert client_handshake._main_state == "READY", (
        f"Actual State: {client_handshake._main_state}")
    assert client_handshake._username_state == "READY", (
        f"Actual State: {client_handshake._username_state}")
    assert server_handshake._state == "READY", f"Actual State: {server_handshake._state}"
    assert received_index == len(test_data), f"Messages Sent: {received_index}"
