from math_utils import fast_exponentiation, gcd, randint
import subprocess
import base64
import subprocess

class RSA:
    def __init__(self):
        self.keys_dir = "keys"
        self.key_paths = {
            "p": f"{self.keys_dir}/private/p.pem",
            "q": f"{self.keys_dir}/private/q.pem",
            "inv_e": f"{self.keys_dir}/private/inv_e.pem",
            "n": f"{self.keys_dir}/public/n.pem",
            "e": f"{self.keys_dir}/public/e.pem"
        }
        subprocess.run(["bash", "create-files.sh"])
        self.create_keys()

    def encrypt(self, M: int) -> int:
        n = self.load_pem_key(self.key_paths["n"])
        e = self.load_pem_key(self.key_paths["e"])
        return fast_exponentiation(M, e, n)

    def decrypt(self, M: int) -> int:
        n = self.load_pem_key(self.key_paths["n"])
        inv_e = self.load_pem_key(self.key_paths["inv_e"])
        return fast_exponentiation(M, inv_e, n)

    def create_keys(self, key_size: int = 2048) -> None:
        p = self.get_random_prime(key_size // 2)
        q = self.get_random_prime(key_size // 2)
        n = p * q
        phi_n = (p - 1) * (q - 1)

        e = self.gen_public_exponent(phi_n)
        inv_e = self.multiplicative_inverse(e, phi_n)

        subprocess.run(["bash", "create-files.sh"])
        self.create_pem_key(p, self.key_paths["p"])
        self.create_pem_key(q, self.key_paths["q"])
        self.create_pem_key(inv_e, self.key_paths["inv_e"])
        self.create_pem_key(n, self.key_paths["n"])
        self.create_pem_key(e, self.key_paths["e"])

    def create_pem_key(self, value: int, path: str) -> None:
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')
        b64 = base64.encodebytes(value_bytes).decode('ascii')
        pem = "-----BEGIN RSA KEY-----\n"
        pem += b64
        pem += "-----END RSA KEY-----\n"

        with open(path, 'w') as f:
            f.write(pem)
        return

    def load_pem_key(self, path: str) -> int:
        with open(path, 'r') as f:
            pem = f.read()
        pem_lines = pem.strip().splitlines()
        b64 = ''.join(line for line in pem_lines if "RSA KEY" not in line)
        value_bytes = base64.decodebytes(b64.encode('ascii'))
        return int.from_bytes(value_bytes, byteorder='big')

    def extended_gcd(self, a: int, b: int)-> tuple[int, int, int]:
        x, y = 1, 0
        aux_x, aux_y = 0, 1
        aux_a, aux_b = a, b
        
        while (aux_b) :
            q = aux_a // aux_b
            (x, aux_x) = (aux_x, x - q * aux_x)
            (y, aux_y) = (aux_y, y - q * aux_y)
            (aux_a, aux_b) = (aux_b, aux_a - q * aux_b)
        return (aux_a, x, y)
    
    def multiplicative_inverse(self, e: int, phi_n:int) -> int:
        (g, inv_e, d) = self.extended_gcd(e, phi_n)
        return inv_e % phi_n
    
    def miller_composite_test(self, a : int, n : int, t : int, q : int) -> bool:
        r = fast_exponentiation(a, q, n)
        
        if (r == n-1 or r == 1): 
            return False

        for r in range(1, t):
            r = (r * r) % n
            if (r == n-1): 
                return False
        return True
    
    def simplify_n_minus_1(self, n: int) -> int:
        t = 0   
        q = n-1
        while(q % 2 == 0):
            q//= 2
            t+= 1

        return (t, q)


    def miller_rabin(self, n: int, its: int = 40) -> bool:
        if n <= 4: 
            return (n == 2 or n == 3)
        
        (t, q) = self.simplify_n_minus_1(n)
        for _ in range(its):
            a = randint(2, n-2)
            if (self.miller_composite_test(a, n, t, q)): 
                return False
        return True


    def get_random_prime(self, msb: int = 2048) -> int:
        p = randint(1 << (msb-1), (1 << (msb)) - 1)
        if p % 2 == 0: 
            p += 1
        while True:
            if self.miller_rabin(p): 
                return p
            p += 2
            if p >= (1 << (msb)):
                p = (1 << (msb-1)) + 1

    def gen_public_exponent(self, phi_n:int) -> int:
        e = randint(2, phi_n-1)
        if e % 2 == 0: 
            e += 1

        while gcd(e, phi_n) != 1:
            e += 2
            if e >= phi_n: 
                e = 3
        return e
