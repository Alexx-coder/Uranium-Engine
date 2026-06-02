from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def ecdh_shared_secret(private_key, peer_public) -> bytes:
    """
    Compute shared secret using X25519 ECDH.
    Accepts either PEM strings or key objects.
    """
    if isinstance(private_key, str):
        private_key = serialization.load_pem_private_key(
            private_key.encode(),
            password=None
        )
    
    if isinstance(peer_public, str):
        peer_public = serialization.load_pem_public_key(
            peer_public.encode()
        )
    
    return private_key.exchange(peer_public)