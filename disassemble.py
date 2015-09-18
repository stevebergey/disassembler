#!/usr/bin/env python3

"""
    Python disassembler for a limited x86 instruction set.
"""

from binascii import hexlify, unhexlify
from constants import *



def parse_modrm_byte(modrmByte):
    """ Takes a modrm byte and parses it into the MOD, REG, and R/M fields.

    Args:
        modrmByte (byte): The modrm byte to be parsed

    Returns:
        fieldList (list): The MOD, REG, and R/M fields as a list in that order.
    """

    mod = (int(modrmByte, 16) >> 6) & 7
    reg = (int(modrmByte, 16) >> 3) & 7
    rm = int(modrmByte, 16) & 7

    return [mod, reg, rm]


def parse_sib_byte(sibByte):
    """ Takes a sib byte and parses it into the SCALE, INDEX, and BASE fields.


    Args:
        sibByte (byte): The sib byte to be parsed

    Returns:
        fieldList (list): The SCALE, INDEX, and BASE fields as a list in that
        order.
    """

    scale = (int(sibByte, 16) >> 6) & 7
    index = (int(sibByte, 16) >> 3) & 7
    base = int(sibByte, 16) & 7

    return [scale, index, base]

def linear_sweep(file, start_address):
    """ Perform a Linear Sweep Disassembly from the start_address.

    Takes a starting address and disassembles it using a Linear Sweep algorithm.
    When an unconditional jump is encountered, dissasembly stops and the jump
    location is added to a queue. Disassembly also stops when a return or call
    is encountered.

    Args:
        file (file): File to be disassembled.
        start_address (int): The address to begin disassembly at

    Returns:

    """

    current_address = start_address
    f = file

    byte = f.read(1)

    while byte:
        byte = hexlify(byte)

        print(byte)

        current_address += 1
        byte = f.read(1)

    print current_address


def main():
    #@TODO Get file from command line
    f = open('ex1', 'rw')
    linear_sweep(f, 0)

    f.close()

    exit()

if __name__ == "__main__":
    main()
