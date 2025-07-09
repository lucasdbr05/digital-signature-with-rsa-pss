from RSA import RSA
from RSA_PSS import RSAPSS


if __name__ == "__main__":
    rsa = RSA()
    print("RSA TESTE")
    x = rsa.encrypt(450)
    print(f"cipher : {x}", end="\n\n")

    print(f"plain: {rsa.decrypt(x)}")
    print("--------\n")
    m = b"Fluminense Futebol Clube"
    fake_m = b"Fuluminense Futebol Clube"

    pss = RSAPSS(salt_len=32)

    signature, salt = pss.sign(m)
    print("Assinatura:", signature)
    print("Salt:", salt.hex())

    valid = pss.verify(m, signature, salt)
    print("is valid?", valid)

    invalid = pss.verify(fake_m, signature, salt)
    print("is valid?:", invalid)