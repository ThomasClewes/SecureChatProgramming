""" module doc string"""
import peer_packets
from .peer_packets import *
from ._recipient_state_machine import *
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


