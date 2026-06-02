from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import secrets
import base64 as b64

"""
For generation keys: ed25519 and x25519 using serialization
"""

def generation_x25519_keypair() -> dict:
    """Generate a x25519 key pair and return them as PEM strings"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
   
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return {
        "private_pem": private_pem,
        "public_pem": public_pem
    }
    

def generation_key() -> dict:
    """Generation Key For ChaCha20"""
    key = secrets.token_bytes(32)
    return {
        "Hex": key.hex(),
        "Base64": b64.b64encode(key).decode('utf-8')
    }
    
    
    
    