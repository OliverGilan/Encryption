#!/usr/bin/python3

import os.path
import sys
import binascii


def get_next_key_byte(seed):
    m = 256
    a = 1103515245
    c = 12345
    return ((a * seed) + c) % m


def hash_password(password):
    hashed = 0
    for i in range(len(password)):
        hashed = ord(password[i]) + (hashed << 6) + (hashed << 16) - hashed
    return hashed


# seed = hash_password("yeet")
# byte = get_next_key_byte(seed)
# for i in range(5):
#     print(byte)
#     byte = get_next_key_byte(byte)
args = sys.argv
debug = 0
password = None
plaintext = None
ciphertext = None
if len(args) < 4:
    print("Error: missing arguments")
    exit()
if args[1] == "-d":
    debug = 1
    password = args[2]
    plaintext = args[3]
    ciphertext = args[4]
else:
    password = args[1]
    plaintext = args[2]
    ciphertext = args[3]

seed = hash_password(password)
if debug == 1:
    print("using seed={} from password={}".format(seed, password))
with open(plaintext, "rb") as pt:
    with open(ciphertext, "wb+") as ct:
        keybyte = get_next_key_byte(seed)
        while True:
            byte = pt.read(1)
            if not byte:
                break
            encrypted = ord(byte) ^ keybyte
            if debug == 1:
                print(
                    "{}({}) xor {} = {}({})".format(
                        hex(ord(byte)),
                        byte,
                        hex(keybyte),
                        hex(encrypted),
                        chr(encrypted),
                    )
                )
            ct.write(bytes([encrypted]))
            keybyte = get_next_key_byte(keybyte)
