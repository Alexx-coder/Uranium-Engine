# **Uranium Engine**
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Uranium Engine** - **It's cryptographic engine for Hybrid Encryption and Hybrid Quantum Encryption (In development). `We are using secure and modern cryptographic algorithms.` This modele was created for secure and fast usage**

> **Developer: `Alexx-coder or alexx (GitHub)`**

> **Version: `0.10.0`**

> **License: `Apache License 2.0`**

> **[Uranium Engine on Github](https://github.com/Alexx-coder/Uranium-Engine.git)**

> **Install:**

```bash
pip install Uranium-Engine
```

## Acknowledgements

**This project uses:**
- **[cryptography](https://github.com/pyca/cryptography) `(Apache-2.0)`**

- **[pqcrypto](https://github.com/backbone-hq/pqcrypto.git) `(MIT)`**

---

# **Modules: Technologies and how use**

> **Everything is available 1 module and 1 module in development**

> **For modules need generation keys, example:**

```python
from UraniumEngine.core.keys import generation_x25519_keypair, generation_key

x25519_keys = generation_x25519_keypair()
public_pem = x25519_keys['public_pem']
private_pem = x25519_keys['private_pem']

key = generation_key()
hex_key = key["Hex"]
base64_key = key["Base64"]
```



## **HybridUranium**

- More detailed:

| Technologies (Python) |
|-----------------------|
| `ECDH`, `X25519`, `ChaCha20-Poly1305` |

- How import:

```python
from UraniumEngine import HybridUranium
```

- How use:

```python
from UraniumEngine import HybridUranium
from UraniumEngine.core.keys import generation_x25519_keypair

# I'll use an example to show Alice and Bob.

alice = generation_x25519_keypair() # Alice generates x25519 keys

secret = b'My name is Bob' # Message's Bob
encrypted = HybridUranium.encrypt(secret, alice['public_pem']) # Encrypting message's Bob

decrypted = HybridUranium.decrypt(encrypted[0], encrypted[1], alice['private_pem']) # Alice decrypts message's Bob
message = decrypted.decode('utf-8') # Decode decryptes message's Bob
print(f"Message's Bob: {message}")  # Print the original message
```



## **HybridQuantumUranium**

> **This module in development...**


---