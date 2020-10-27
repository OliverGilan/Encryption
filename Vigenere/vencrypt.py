#!/usr/bin/python3

import sys
import os.path


def readKey(filename):
    key = None
    with open(filename) as fp:
        key = fp.readline()
    return key


debug = 0
key = None
plaintext = None
ciphertext = None
args = sys.argv

if len(args) < 4:
    print("Error: Missing arguments\n")
    exit()

if args[1] == "-d":
    debug = 1
    if args[2] == "-k":
        key = args[3]
        plaintext = args[4]
        ciphertext = args[5]
    else:
        key = readKey(args[2])
        plaintext = args[3]
        ciphertext = args[4]
elif args[1] == "-k":
    key = args[2]
    plaintext = args[3]
    ciphertext = args[4]
else:
    key = readKey(args[1])
    plaintext = args[2]
    ciphertext = args[3]

keyindex = 0
pbyte = None

with open(plaintext, "r") as pt:
    with open(ciphertext, "wb+") as ct:
        while True:
            pbyte = pt.read(1)
            if not pbyte:
                break
            pbyte = ord(pbyte)
            c = ord(key[keyindex])
            encrypted = (pbyte + c) % 256
            # print(encrypted)
            # print(chr(encrypted))
            if debug == 1:
                print(
                    "looking up table[{}({})][{}({})] = {}({})".format(
                        pbyte, chr(pbyte), c, key[keyindex], encrypted, chr(encrypted)
                    )
                )
            ct.write(bytes([encrypted]))
            keyindex = (keyindex + 1) % len(key)