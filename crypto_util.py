import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)


# Using AES-GCM for the Encryption process


def encrypt_data(key, data):
    aesgcm_value = AESGCM(key)
    nonce = os.urandom(12)  # required size for GCM

    ciphertext = aesgcm_value.encrypt(nonce, data, None)

    completed_ciphertext = nonce + ciphertext
    return completed_ciphertext  # prepend nonce


def decrypt_data(key, encrypted_data):
    if len(encrypted_data) < 12:
        raise ValueError("Invalid encrypted data")
    aesgcm_value = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    result = aesgcm_value.decrypt(nonce, ciphertext, None)

    return result


# SHA-256 (Hashing)

def compute_hash(data):
    return hashlib.sha256(data).hexdigest()


# The signature algorithm we are using is Ed25519

def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_data(private_key, data):
    return private_key.sign(data)


def verify_signature(public_key, data, signature):
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        return False


# Key Serialization
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def load_public_key(data):
    return Ed25519PublicKey.from_public_bytes(data)


def verify_file(data, expected_hash, public_key, signature):
    if compute_hash(data) != expected_hash:
        return False

    if not verify_signature(public_key, data, signature):
        return False

    return True


# For perfect forward secrecy

def generate_ephemeral_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_ephemeral_public(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def load_ephemeral_public(data):
    return x25519.X25519PublicKey.from_public_bytes(data)


def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'p2p-file-transfer',
    )

    return hkdf.derive(shared_secret)