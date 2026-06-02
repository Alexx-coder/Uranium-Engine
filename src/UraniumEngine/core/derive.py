from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hkdf_derive(shared_secret: bytes, length: int = 32) -> bytes:
    """Get the encryption key from the shared secret using HKDF"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'uranium-engine',
    )
    return hkdf.derive(shared_secret)