from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from io import SEEK_END
from typing import Union

CHACHA20_KEY_LENGTH = 32
CHACHA20_NONCE_LENGTH = 12

X25519_KEY_LENGTH = 32

#The functions here are all stringent regarding allowed types.
#I find enforcing this very helpful for debugging and for
#preventing the "weird" errors that are common in languages
#with highly-dynamic type systems.

#loads a pem-formatted RSA public key from file.
def load_public_key(path: str) -> RSAPublicKey:
    if not isinstance(path, str):
        raise TypeError("path must have type string")
    with open(path,"rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )

def load_private_key(path:str) -> RSAPrivateKey:
    path = str(path)
    with open(path,"rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            None
        )

#loads a raw signature from file.
#
#Raises ValueError if the file is not 256 bytes long.
#
#The a valid have been derived using SHA256 hashing,
#PKCS1v15 padding, and 2048-bit RSA. This entails a signature length
#of 2048 bits or 256 bytes
def load_signature(path: str) -> Union[bytes,bytearray]:
    with open(path,"rb") as signature_file:
        signature = signature_file.read(256)
        if len(signature) < 256:
            raise ValueError("Signature is too short")
        current_position = signature_file.tell()
        end_position = signature_file.seek(0,SEEK_END)
        if current_position != end_position:
            raise ValueError("Signature is too long")
        return signature
