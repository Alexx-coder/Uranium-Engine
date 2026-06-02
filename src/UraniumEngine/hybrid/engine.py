from UraniumEngine.core import exchange, keys, derive
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import secrets
import base64

"""Hybrid Encryption Algorithm: working using ECDH, X25519 and ChaCha20-Poly1305.
There are two functions: encrypt and decrypt.

Secure: We are using secure, fast and cryptographic algorithms.
It's secure and reliable algorithm.
"""

class HybridUranium:
    @staticmethod
    def encrypt(data: bytes, peer_public_pem: str) -> tuple:
        """Encrypt data using ECHD, X25519 and ChaCha20
        
        Args:
          data (bytes): message to encrypt,
          peer_public_pem (str): x25519 public key in formate PEM the recipient
          
        Example: on site https://github.com/Alexx-coder/Uranium-Engine.git in README.md
        """
        ephemeral = keys.generation_x25519_keypair()
        
        shared = exchange.ecdh_shared_secret(ephemeral['private_pem'], peer_public_pem)
        
    
        session_key = derive.hkdf_derive(shared)
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(session_key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        result = nonce + ciphertext
        result_b64 = base64.b64encode(result).decode()
        
        return ephemeral['public_pem'], result_b64
    
    @staticmethod
    def decrypt(ephemeral_pub_pem: str, ciphertext_b64: str, recipient_priv_pem: str) -> bytes:
        """Decrypt data using ECDH, X25519 and ChaCha20
        
        Args:
          ephermal_pub_pem (str): public ephermal key the sender,
          ciphertext_b64 (str): encrypted message in base64 ,
          recipient_priv_pem (str): x25519 private key in formate PEM the sender
          
        Example: on site https://github.com/Alexx-coder/Uranium-Engine.git in README.md

        """
        shared = exchange.ecdh_shared_secret(recipient_priv_pem, ephemeral_pub_pem)
        
        session_key = derive.hkdf_derive(shared)
        
        data = base64.b64decode(ciphertext_b64)
        nonce = data[:12]
        ciphertext = data[12:]
        
        cipher = ChaCha20Poly1305(session_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext