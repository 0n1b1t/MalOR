import struct
from Crypto.Cipher import ARC4, DES, DES3, AES, Blowfish, XOR
from Crypto.PublicKey import RSA
from pbkdf2 import PBKDF2


# RSA
def decrypt_rsa(key, data):
    rsa_key = RSA.importKey(key)
    return rsa_key.decrypt(data)


# XOR
def decrypt_xor(key, data):
    cipher = XOR.new(key)
    return cipher.decrypt(data)


# RC4
def decrypt_arc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


# DES
def decrypt_des_ecb(key, data, iv=None):
    mode = DES.MODE_ECB
    if iv:
        cipher = DES.new(key, mode, iv)
    else:
        cipher = DES.new(key, mode)
    return cipher.decrypt(data)


def decrypt_des_cbc(key, data, iv=None):
    mode = DES.MODE_CBC
    if iv:
        cipher = DES.new(key, mode, iv)
    else:
        cipher = DES.new(key, mode)
    return cipher.decrypt(data)


# DES3
def decrypt_des3(key, data):
    cipher = DES3.new(key)
    return cipher.decrypt(data)


# AES
def decrypt_aes(key, data):
    cipher = AES.new(key)
    return cipher.decrypt(data)


def decrypt_aes_cbc_iv(key, iv, data):
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode, IV=iv)
    return cipher.decrypt(data)


# Blowfish
def decrypt_blowfish(key, data):
    cipher = Blowfish.new(key)
    return cipher.decrypt(data)


# RC6 - Custom
def decrypt_RC6(key, encrypted, P, Q, rounds):
    def rol(a, i):
        a &= 0xFFFFFFFF
        i &= 0x1F
        x = (((a << i) & 0xFFFFFFFF) | (a >> (32 - i))) & 0xFFFFFFFF
        return x

    def ror(a, i):
        i &= 0x1F
        a &= 0xFFFFFFFF
        return ( ((a >> i) & 0xFFFFFFFF) | (a << ( (32 - i)))) & 0xFFFFFFFF

    def to_int(bytestring):
        if isinstance(bytestring, str):
            bytestring = bytearray(bytestring, 'utf-8')

        l = []
        for i in range(int(len(bytestring)/4)):
            l.append(struct.unpack("<I", bytestring[i*4:(i*4)+4])[0])
        return l

    def decrypt_block(block, S):
        # Decrypt block
        ints = to_int(block)
        ints[0] = (ints[0] - S[T-2])
        ints[2] = (ints[2] - S[T-1])
        for i in reversed(range(rounds)):
            r = i+1

            # rotate ints
            ints = ints[-1:] + ints[:-1]

            tmp1 = rol(ints[3] * (2 * ints[3] + 1), 5)
            tmp2 = rol(ints[1] * (2 * ints[1] + 1), 5)
            ints[2] = ror(ints[2] - S[2 * r + 1], tmp2) ^ tmp1
            ints[0] = ror(ints[0] - S[2 * r], tmp1) ^ tmp2

        ints[3] = ints[3] - S[1]
        ints[1] = ints[1] - S[0]

        # convert to bytes
        decrypted = []
        for i in range(4):
            for j in range(4):
                decrypted.append(ints[i] >> (j * 8) & 0xFF)
        return decrypted

    T = 2 * rounds + 4

    # Expand key
    L = to_int(key)
    S = []
    S = [0 for i in range(T)]
    S[0] = P

    for x in range(T-1):
        S[x+1] = (S[x] + Q) & 0xFFFFFFFF
    i = 0
    j = 0
    A = 0
    B = 0

    for x in range(3*T):
        A = S[i] = rol((S[i] + A + B), 3)
        B = L[j] = rol((L[j] + A + B), (A + B))
        i = (i + 1) % T
        j = (j + 1) % 8

    # Decrypt blocks
    decrypted = []
    while True:
        decrypted += decrypt_block(encrypted[:16], S)
        encrypted = encrypted[16:]
        if not encrypted:
            break
    data = bytearray(decrypted)
    data = data.rstrip(b"\x00")
    return data


# Key Derivation
def derive_pbkdf2(key, salt, iv_length, key_length, iterations=8):
    generator = PBKDF2(key, salt, iterations)
    derived_iv = generator.read(iv_length)
    derived_key = generator.read(key_length)
    return derived_iv, derived_key