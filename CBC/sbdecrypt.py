#!/usr/bin/python3

import os.path
import sys
import binascii
import itertools
import copy


def get_16_bytes(seed, depth):
    m = 256
    a = 1103515245
    c = 12345
    first = ((a * seed) + c) % m
    if depth == 15:
        return str(first)
    return str(first) + get_16_bytes(first, depth + 1)


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
lastkeybyte = seed

if debug == 1:
    print(
        'plaintextfile="{}" ciphertextfile="{}" password="{}"'.format(
            plaintext, ciphertext, password
        )
    )
print("using seed={} from password={}".format(seed, password))
with open(plaintext, "rb") as pt:
    with open(ciphertext, "wb+") as ct:
        # File size
        size = os.path.getsize(plaintext)
        # Create Initialization Vector with 16 bytes
        iv = [get_next_key_byte(seed)]
        for i in range(16):
            iv.append(get_next_key_byte(iv[-1]))
        lastkeybyte = iv[-1]

        # iv = bytearray(iv, encoding="utf8")
        while True:
            if debug == 1:
                print("")
            cipherblock = bytearray(pt.read(16))
            if len(cipherblock) == 0:
                break
            size = size - 16
            prev = copy.deepcopy(cipherblock)

            # Read 16 bytes from stream
            stream = [lastkeybyte]
            for i in range(16):
                stream.append(get_next_key_byte(stream[-1]))
                lastkeybyte = stream[-1]

            for i in range(16):
                cipherblock[i] = cipherblock[i] ^ stream[i]

            if debug == 1:
                print(
                    "encrypted block before shuffle: {}".format(
                        list(map(lambda x: hex(x)[2:], prev))
                    )
                )
                print(
                    "after xor with keystream: {} - scrambled".format(
                        list(map(lambda x: hex(x)[2:], cipherblock))
                    )
                )

            # Shuffle bytes
            for i in reversed(range(16)):
                keybyte = stream[i]
                first = keybyte & 0xF
                second = (keybyte >> 4) & 0xF
                swapped = cipherblock[first]
                cipherblock[first] = cipherblock[second]
                cipherblock[second] = swapped
                if debug == 1:
                    print(
                        "{}: swapping ({}, {}) = [{} <> {}]".format(
                            i,
                            first,
                            second,
                            hex(cipherblock[second])[2:],
                            hex(cipherblock[first])[2:],
                        )
                    )

            if debug == 1:
                print(
                    "plaintext?: {}".format(
                        list(map(lambda x: hex(x)[2:], cipherblock))
                    )
                )

            for i in range(16):
                cipherblock[i] = cipherblock[i] ^ iv[i]

            if size == 0:
                diff = 16 - cipherblock[-1]
                if diff == 0:
                    break
                cipherblock = cipherblock[:diff]

            ct.write(bytearray(int(i) for i in cipherblock))
            iv = prev
