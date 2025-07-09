from RSA import RSA

rsa = RSA()

x = rsa.encrypt(450)
print(x, end="\n\n")

print(rsa.decrypt(x))