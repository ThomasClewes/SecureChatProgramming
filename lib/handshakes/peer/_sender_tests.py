from . import peer_packets
from .peer_packets import *
from ._sender_state_machine import *
from lib.protocol import PACKETS
#can't do import lib.handshakes as handshake followed by handshakes.server
import lib.handshakes.peer as handshake_module
import lib.crypt as crypt

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from base64 import b64encode
import os

from . import _sender_tests as self_module

def test_all():
    print('Running sender tests')
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
    handshake = SenderStateMachine("bob","alice")
    call_flag = False 

    def test_packet(type, serialized_packet):
        nonlocal call_flag
        call_flag = True

        assert type == PACKETS["RECIPIENT_HELLO"],\
            f"Expected CLIENT_HELLO, found {INV_PACKETS.get(type,'INVALID')}"

        recipient_hello = RecipientHello.deserialize(serialized_packet)

        #dont believea this is how original bytes are recieved to be checked
        #not sure how to get original bytes
        original_random_bytes = handshake.recipient_random
        original_key_bytes = _format_x25519_public(
            handshake.recipient_ephemeral_public_key)

        received_random_bytes = recipient_hello.recipient_random
        received_key_bytes = recipient_hello.recipient_ephemeral_public_key

        assert \
            original_random_bytes == received_random_bytes, \
            "Recipient random was not recovered after deserialization:\n\t" \
            + f"original: {original_random_bytes}\n\t" \
            + f"received: {received_random_bytes}"

        assert \
            original_key_bytes == received_key_bytes, \
            "Recipient random was not recovered after deserialization:\n\t" \
            + f"original: {original_key_bytes}\n\t" \
            + f"received: {received_key_bytes}"

def test_receive_recipient_hello():
    ca_private_key = rsa.generate_private_key(
        65537,
        2048)
    ca_public_key = ca_private_key.public_key()

    client_username = "bob"
    peer_username = "alice"

    handshake = SenderStateMachine(client_username,peer_username)
    handshake._generate_parameters()
    handshake._state = "WAITING_FOR_HELLO"

    sender_random = os.urandom(handshake_module.RANDOM_LENGTH)
    sender_ephemeral_private_key = X25519PrivateKey.generate()
    sender_ephemeral_public_key = sender_ephemeral_private_key.public_key()
    sender_persistent_private_key = rsa.generate_private_key(
        65537,
        2048)
    sender_persistent_public_key = sender_persistent_private_key.public_key()

    premaster_key = sender_ephemeral_private_key.exchange(
        handshake.recipient_ephemeral_public_key)

    master_key = (HKDF(
        algorithm = hashes.SHA256(),
        length = handshake_module.crypt.CHACHA20_KEY_LENGTH,
        salt = handshake.recipient_random + sender_random,
        info = None)
        .derive(premaster_key))

    send_key = master_key

    sender_hello = SenderHello(sender_ephemeral_public_key,sender_random)

    serialized_sender_hello = sender_hello.serialize(sender_persistent_private_key)

    call_flag  = False

