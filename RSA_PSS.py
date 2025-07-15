import hashlib
import os 
import base64
from RSA import RSA


class RSAPSS:
    def __init__(self, salt_len: int = 32):
        self.rsa = RSA() 
        self.hash_alg = 'sha256'  
        self.salt_len = salt_len  
    
    def sign(self, message: bytes) -> tuple[str, str]:
        """
        EM = 0x00 || 0x01 || PS || 0x00 || H(M) || SALT
        """
        em_len = self.get_em_length()

        hlen = hashlib.new(self.hash_alg).digest_size
        message_hash = hashlib.new(self.hash_alg, message).digest() 
        salt = os.urandom(self.salt_len) 
        
        ps_len = em_len - hlen - self.salt_len - 3 
        ps = self.mgf1(message_hash + salt, ps_len, self.hash_alg) 
        
        em = b'\x00' + b'\x01' + ps + b'\x00' + message_hash + salt
        em = int.from_bytes(em, byteorder='big')
        
        signature = self.rsa.decrypt(em) 

        signature_b64 = base64.b64encode(signature.to_bytes(em_len, byteorder='big')).decode()
        salt_b64 = base64.b64encode(salt).decode()
        return (signature_b64, salt_b64)

    def verify(self, message: bytes, signature_b64: str, salt_b64: str) -> bool:
        em_len = self.get_em_length()

        hlen = hashlib.new(self.hash_alg).digest_size
        m_hash = hashlib.new(self.hash_alg, message).digest() 
       
        signature_bytes = base64.b64decode(signature_b64)
        salt = base64.b64decode(salt_b64)
       
        signature = int.from_bytes(signature_bytes, byteorder='big')
        em = self.rsa.encrypt(signature)  
        em = em.to_bytes(em_len, byteorder='big')
        if not (em[0] == 0x00 and em[1] == 0x01):
            return False
        ps_len = em_len - hlen - self.salt_len - 3
        ps = em[2:2+ps_len]
        ps_check = self.mgf1(m_hash + salt, ps_len, self.hash_alg)
        if ps != ps_check:
            return False
        if em[2+ps_len] != 0x00:
            return False
        m_hash2 = em[3+ps_len:3+ps_len+hlen]
        salt2 = em[3+ps_len+hlen:]
        return m_hash2 == m_hash and salt2 == salt

    def mgf1(self, seed: bytes, mask_len: int, hash_alg: str = 'sha256') -> bytes:
        hlen = hashlib.new(hash_alg).digest_size
        mask = b''
        for i in range((mask_len + hlen - 1) // hlen):
            c = i.to_bytes(4, byteorder='big')
            mask += hashlib.new(hash_alg, seed + c).digest()
        return mask[:mask_len]  
    
    def get_em_length(self) -> int:
        n = self.rsa.load_pem_key(self.rsa.key_paths["n"])
        return (n.bit_length() + 7) // 8