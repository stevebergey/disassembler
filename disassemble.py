#!/usr/bin/env python3

"""
    Python disassembler for a limited x86 instruction set.
"""

from binascii import hexlify, unhexlify
from constants import *


def endian_swap_32(hex32):
    return hex32[6:8] + hex32[4:6] + hex32[2:4] + hex32[0:2]

def init_disassembly():
    """ Erases the disassembly.tmp file for writing
    """
    f = open("disassembly.tmp", 'w')
    f.close()

    return

def add_to_disassembly(f, addr, length, disassembly):
    """Adds line of dissassembly to disassembly file.

    Args:
        f (file): File being disassembled.
        address (int): Address of instruction being added
        length (int): Number of bytes in instruction
        disassembly (string): String containing (mnemonic op1, op2)
    """

    f_pos = f.tell()    #save current file position
    dis_line = ""
    ins_bytes = ""

    f.seek(addr)
    ins_bytes = f.read(length)
    dis_line = str(addr) + " " + hexlify(ins_bytes) + " " + disassembly + "\n"

    f = open("disassembly.tmp", "a")
    f.write(dis_line)

    f.seek(f_pos)   #restore file position

    return

def get_instruction_row(opcode):
    """Takes an opcode string and returns its row in the instruction table.

    Args:
        opcode (string): The opcode whose row you want to return

    Returns:
        row_index (int): Row index into instruction table of opcode's
        instruction.
        None: Returned if opcode not found.
    """

    for row in instruction_table:
        a = row
        b = row[c_opcode]
        if row[c_opcode] == opcode:
            return instruction_table.index(row)

    return None

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
    ins_start_addr = start_address
    in_instruction = False
    disas = ""
    row = None
    sum_op_flag = False
    tmp_op = None           #used for setting opcode for summed ops
    f = file

    byte = f.read(1)
    byte = hexlify(byte)

    # loop over bytes
    while byte:

        if in_instruction:
            ins = instruction_table[row]

            # handle RM/REG cases
            if ins[c_rmreg] == "NONE":
                if ins[c_ins1] == "EAX":
                    disas = instruction_table[row][c_mnemonic] + " EAX, "
                    if ins[c_ins2] == "imm8":
                        disas = disas + hexlify(f.read(1))
                        current_address += 1
                        add_to_disassembly(f, ins_start_addr, 2, disas)

                    elif ins[c_ins2] == "imm32":
                        disas = disas + endian_swap_32(hexlify(f.read(4)))
                        current_address += 4
                        add_to_disassembly(f, ins_start_addr, 5, disas)
                    else:
                        print("Error: Unsupported immediate at instruction " +
                              int(ins_start_addr))
                elif ins[c_ins1] == "imm8":
                    disas = instruction_table[row][c_mnemonic] + " "
                    disas = disas + hexlify(f.read(1))
                    current_address += 1
                    add_to_disassembly(f, ins_start_addr, 2, disas)

                elif ins[c_ins1] == "imm32":
                    disas = instruction_table[row][c_mnemonic] + " "
                    disas = disas + endian_swap_32(hexlify(f.read(4)))
                    current_address += 4
                    add_to_disassembly(f, ins_start_addr, 5, disas)

                else:
                    print("Error: Unsupported ins1 value " +
                          ins[c_ins1])

                in_instruction = False

            elif ins[c_rmreg] == "c32":
                pass
            elif ins[c_rmreg] == "c8":
                pass
            elif ins[c_rmreg] == "r":
                pass
            elif (int(ins[c_rmreg]) >= 0) and (int(ins[c_rmreg]) <= 7):
                pass
            else:
                print("Error: Unsupported regrm optable value " + ins[c_rmreg])
                in_instruction = False

            current_address += 1
            byte = f.read(1)
            byte = hexlify(byte)


        # When not in the middle of parsing instruction...
        if not in_instruction:
            in_instruction = True
            row = None
            ins_start_addr = current_address

            # 1) Determine Opcode

            # Addition-based opcodes
            if(int(byte, 16) >= 0x40 and int(byte, 16) <= 0x47):
                op1 = int(byte, 16) - 0x40
                tmp_op = "40"
                sum_op_flag = True

            elif (int(byte, 16) >= 0x48 and int(byte, 16) <= 0x4F):
                op1 = int(byte, 16) - 0x48
                tmp_op = "48"
                sum_op_flag = True

            elif (int(byte, 16) >= 0x50 and int(byte, 16) <= 0x57):
                op1 = int(byte, 16) - 0x50
                tmp_op = "50"
                sum_op_flag = True

            elif (int(byte, 16) >= 0x58 and int(byte, 16) <= 0x5F):
                op1 = int(byte, 16) - 0x58
                tmp_op = "58"
                sum_op_flag = True

            elif (int(byte, 16) >= 0xB8 and int(byte, 16) <= 0xBF):
                op1 = int(byte, 16) - 0xB8
                tmp_op = "B8"
                sum_op_flag = True

            # if opcode is a sum opcode...
            if sum_op_flag:
                row = get_instruction_row(tmp_op)
                if row is None:
                    print("Error: Opcode not found.")
                else:
                    disas = instruction_table[row][c_mnemonic] + " " + \
                            registers[op1]

                    #handle odd-case addition-based op (mov reg, imm32)
                    if tmp_op == "B8":
                        imm32 = hexlify(f.read(4))
                        imm32 = endian_swap_32(imm32)
                        disas = disas + ", 0x" + imm32

                    add_to_disassembly(f, ins_start_addr, 1, disas)

                if tmp_op == "B8":
                    current_address += 4
                in_instruction = False
                sum_op_flag = False     #Reset flag
            # END ADDITION-BASED OPCODE

            #if 0x0F then it's a two byte opcode. Read another byte.
            if byte == "0F":
                byte = byte + hexlify(f.read(1))
                current_address += 1

            row = get_instruction_row(byte)

            if row is None:
                print("Error: Opcode not found. Interpreting as data.")
                disas = "db '" + byte + "'"
                add_to_disassembly(f, ins_start_addr, 1, disas)
                in_instruction = False

            # Check if single byte op
            if (instruction_table[row][c_rmreg] == "NONE"
                and instruction_table[row][c_ins1] == "NONE"
                and instruction_table[row][c_ins2] == "NONE"):
                disas = instruction_table[row][c_mnemonic]
                add_to_disassembly(f, ins_start_addr, 1, disas)
                in_instruction = False



            #END NOT IN INSTRUCTION

        current_address += 1
        byte = f.read(1)
        byte = hexlify(byte)
        #END BYTE WHILE LOOP

    print current_address


def main():
    #@TODO Get file from command line
    init_disassembly()

    f = open('test', 'rw')
    linear_sweep(f, 0)

    f.close()
    exit()

if __name__ == "__main__":
    main()
