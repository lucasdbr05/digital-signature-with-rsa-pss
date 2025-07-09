import sys
from random import randint
sys.setrecursionlimit(10000)

def gcd(a: int, b: int) -> int:
    if(a==0):
        return b 
    return gcd(b%a, a)

def fast_exponentiation(b:int, e:int, MOD: int) ->int:
    value = 1
    b %= MOD
    while (e > 0) :
        if (e & 1):
            value = value * b % MOD
        b = (b * b) % MOD
        e >>= 1

    return value

