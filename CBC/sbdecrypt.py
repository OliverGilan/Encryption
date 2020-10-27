#!/usr/bin/python3

import os.path
import sys
import binascii
import itertools


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
padded = False

if debug == 1:
    print(
        'plaintextfile="{}" ciphertextfile="{}" password="{}"'.format(
            plaintext, ciphertext, password
        )
    )
print("using seed={} from password={}".format(seed, password))

with open(plaintext, "r") as pt:
    with open(ciphertext, "wb+") as ct:
        # Create Initialization Vector with 16 bytes
        iv = [get_next_key_byte(seed)]
        for i in range(16):
            iv.append(get_next_key_byte(iv[-1]))
        lastkeybyte = iv[-1]
        # iv = bytearray(iv, encoding="utf8")
        while True:
            print("")
            # Read 16 blocks from input file
            block = pt.read(16)
            # If EOF, quit
            if not block:
                break
            blockbytes = bytearray(block, encoding="utf8")

            # Add Padding
            if len(blockbytes) < 16:
                diff = 16 - len(blockbytes)
                blockbytes.extend(itertools.repeat(diff, diff))
                padded = True

            # XOR with previous cipherblock or IV
            temp = []
            for i in range(16):
                temp.append(blockbytes[i] ^ iv[i])

            if debug == 1:
                print(
                    "before shuffle: {}".format(list(map(lambda x: hex(x)[2:], temp)))
                )

            # Read 16 bytes of keystream
            keybyte = lastkeybyte
            stream = [keybyte]
            # Swap 16 pairs of bytes and read bytes from keystream
            for i in range(16):
                first = keybyte & 0xF
                second = (keybyte >> 4) & 0xF
                swapped = temp[first]
                temp[first] = temp[second]
                temp[second] = swapped
                keybyte = get_next_key_byte(keybyte)
                lastkeybyte = keybyte
                stream.append(keybyte)
                if debug == 1:
                    print(
                        "{}: swapping ({}, {}) = [{} <> {}]".format(
                            i,
                            first,
                            second,
                            hex(temp[second])[2:],
                            hex(temp[first])[2:],
                        )
                    )

            if debug == 1:
                print("after shuffle: {}".format(list(map(lambda x: hex(x)[2:], temp))))

            # Create cipherblock
            cipherblock = []
            for i in range(16):
                cipherblock.append(temp[i] ^ stream[i])

            if debug == 1:
                print(
                    "after xor with keystream: {}".format(
                        list(map(lambda x: hex(x)[2:], cipherblock))
                    )
                )

            # Write ciphertext
            ct.write(bytearray(int(i) for i in cipherblock))

            # Set initialization vector to current cipherblock
            iv = cipherblock