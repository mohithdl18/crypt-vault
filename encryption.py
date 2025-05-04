from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public.pem")

# Ensure keys exist
def generate_keys():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    if not os.path.isfile(PRIVATE_KEY_FILE) or not os.path.isfile(PUBLIC_KEY_FILE):
        # Generate RSA private and public keys
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Save private key
        with open(PRIVATE_KEY_FILE, "wb") as priv_file:
            priv_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save public key
        with open(PUBLIC_KEY_FILE, "wb") as pub_file:
            pub_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def encrypt_data(data: bytes) -> bytes:
    with open(PUBLIC_KEY_FILE, "rb") as pub_file:
        public_key = serialization.load_pem_public_key(pub_file.read())

    encrypted_data = public_key.encrypt(
        data[:190],  # Max size limit of RSA 2048 (~190 bytes)
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

def decrypt_data(data: bytes) -> bytes:
    with open(PRIVATE_KEY_FILE, "rb") as priv_file:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None)

    decrypted_data = private_key.decrypt(
        data,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

# Generate keys (run once, will only generate if the keys do not exist)
generate_keys()
