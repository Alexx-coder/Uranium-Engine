from UraniumEngine.core import keys, exchange, derive

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt


"""
Hybrid Quantum Encryption Algorithm:
Uses X25519 + ML-KEM-768 + HKDF.

Post-quantum + classical hybrid security.
"""

class HybridQuantumUranium:
    @staticmethod
    def generate_keypair():
        """Generate hybrid keypair."""

        x25519_kp = keys.generation_x25519_keypair()

        pk_kem, sk_kem = generate_keypair()

        return {
            'private_x25519': x25519_kp['private_pem'],
            'public_x25519': x25519_kp['public_pem'],
            'private_kem': sk_kem,
            'public_kem': pk_kem
        }

    @staticmethod
    def encapsulate(peer_public_x25519: str, peer_public_kem: bytes):
        """
        Sender:
        X25519 ECDH + ML-KEM encapsulation
        """

        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key()

        eph_priv_pem = eph_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        eph_pub_bytes = eph_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        shared_classic = exchange.ecdh_shared_secret(
            eph_priv_pem,
            peer_public_x25519
        )

        ciphertext_kyber, shared_kyber = encrypt(bytes(peer_public_kem))

        combined = shared_classic + shared_kyber

        session_key = derive.hkdf_derive(combined)

        return eph_pub_bytes, ciphertext_kyber, session_key

    @staticmethod
    def decapsulate(
        eph_pub,
        ciphertext_kyber: bytes,
        receiver_private_x25519: str,
        receiver_private_kem: bytes
    ) -> bytes:
        """
        Receiver:
        Recover shared secret
        """

        if isinstance(eph_pub, bytes):
            temp_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub)

            eph_pub_pem = temp_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            eph_pub_pem = eph_pub

        shared_classic = exchange.ecdh_shared_secret(
            receiver_private_x25519,
            eph_pub_pem
        )

        shared_kyber = decrypt(
            ciphertext_kyber,
            bytes(receiver_private_kem)
        )

        combined = shared_classic + shared_kyber

        return derive.hkdf_derive(combined)