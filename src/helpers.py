import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from typing import Any

from constants import KEYS_DIR

def clear() -> None:
    """
    Clears the terminal screen.
    """
    os.system("cls" if os.name == "nt" else "clear")

def generateKeys(user1: str, user2: str) -> None:
    """
    Generate RSA key pairs for two users and save them to files.
    
    Args:
        user1 (str): Name of the first user
        user2 (str): Name of the second user
        
    The function will create the following files:
    - {user1}_private.pem: Private key for user1
    - {user1}_public.pem: Public key for user1
    - {user2}_private.pem: Private key for user2
    - {user2}_public.pem: Public key for user2
    """
    # Generate key pairs for both users
    for user in [user1, user2]:
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Generate public key
        public_key = private_key.public_key()
        
        # Save private key
        with open(f"{KEYS_DIR}/{user}_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        with open(f"{KEYS_DIR}/{user}_public.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def encrypt(keyFilePath: str, message: str) -> bytes:
    """
    Encrypts a message using RSA encryption with the specified key file.
    
    Args:
        keyFilePath (str): Path to the key file (public or private key)
        message (str): The message to encrypt
        
    Returns:
        bytes: The encrypted message
        
    Raises:
        ValueError: If the key file cannot be loaded or if encryption fails
    """
    try:
        # Read the key file
        with open(keyFilePath, "rb") as keyFile:
            keyData: bytes = keyFile.read()
            
        # Try to load as public key first
        try:
            key: Any = serialization.load_pem_public_key(keyData, backend=default_backend())
            if not isinstance(key, rsa.RSAPublicKey):
                raise ValueError("Key file must contain an RSA public key")
        except ValueError:
            # If not public key, try private key
            privateKey: Any = serialization.load_pem_private_key(keyData, password=None, backend=default_backend())
            if not isinstance(privateKey, rsa.RSAPrivateKey):
                raise ValueError("Key file must contain an RSA private key")
            key = privateKey.public_key()
            
        # Convert message to bytes
        messageBytes: bytes = message.encode()
        
        # Encrypt the message
        encryptedMessage: bytes = key.encrypt(
            messageBytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encryptedMessage
        
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt(keyFilePath: str, encryptedMessage: bytes) -> str:
    """
    Decrypts a message using RSA decryption with the specified private key file.
    
    Args:
        keyFilePath (str): Path to the private key file
        encryptedMessage (bytes): The encrypted message to decrypt
        
    Returns:
        str: The decrypted message
        
    Raises:
        ValueError: If the key file cannot be loaded, if it's not a private key, or if decryption fails
    """
    try:
        # Read the key file
        with open(keyFilePath, "rb") as keyFile:
            keyData: bytes = keyFile.read()
            
        # Load the private key
        privateKey: Any = serialization.load_pem_private_key(keyData, password=None, backend=default_backend())
        if not isinstance(privateKey, rsa.RSAPrivateKey):
            raise ValueError("Key file must contain an RSA private key")
            
        # Decrypt the message
        decryptedMessage: bytes = privateKey.decrypt(
            encryptedMessage,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Convert bytes back to string
        return decryptedMessage.decode()
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
