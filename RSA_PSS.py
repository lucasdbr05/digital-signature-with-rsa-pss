import hashlib
import os 
from RSA import RSA

class RSA_PSS:
    def __init__(self, salt_len: int = 32):
        self.rsa = RSA()
        self.hash_alg = 'sha256'
        self.salt_len = salt_len

    def sign(self, message: bytes) -> int:
        h = hashlib.new(self.hash_alg, message).digest()
        salt = os.urandom(self.salt_len)
        m_prime = hashlib.new(self.hash_alg, h + salt).digest()
        m_int = int.from_bytes(m_prime, byteorder='big')

        signature = self.rsa.decrypt(m_int)
        
        return (signature, salt)

    def verify(self, message: bytes, signature: int, salt: bytes) -> bool:
        h = hashlib.new(self.hash_alg, message).digest()
        m_prime = hashlib.new(self.hash_alg, h + salt).digest()
        m_int = int.from_bytes(m_prime, byteorder='big')
        
        recovered = self.rsa.encrypt(signature)
        return recovered == m_int
