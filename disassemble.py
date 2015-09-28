#!/usr/bin/env python3

"""
    Python disassembler for a limited x86 instruction set.
"""

import argparse
import os.path
from binascii import hexlify
from constants import *
from math import pow
from time import time


start_time = None       # Used to detect possible infinite loops. If current
infinite_threshold = 5  # time exceeds threshold, user will be prompted on
                        # whether to continue execution or exit.

label_list = []     # Global list containing jmp/call addresses and their
                    # Calculated offset location as (Addr, Loc)
defer_queue = []    # List of addresses being deferred when using recursive
                    # descent.
instructions_written = [] # List of instructions already written to file.
                          # Prevents duplicates from being written.

def is_valid_file(parser, arg):
    """ Check if file exists.
    """
    arg = os.path.abspath(arg)
    if not os.path.exists(arg):
        parser.error("The file " + arg + " does not exist!")
    else:
        return arg

def endian_swap_32(hex32):
    """ Swaps the Endianness of a 32-bit value

    Args:
        hex32 (int): Value to swap endianness

    Returns:
        (int): Swapped 32 bit value
    """

    return hex32[6:8] + hex32[4:6] + hex32[2:4] + hex32[0:2]


def htosi(val):
    """ Converts hex string to signed integer

    Args:
        val (string): Hex string to convert

    Returns:
        uintval (int): signed integer representation.
    """
    uintval = int(val,16)
    bits = 4 * len(val)
    if uintval >= pow(2,bits-1):
        uintval = int(0 - (pow(2,bits) - uintval))
    return uintval


def print_disassembly():
    """Prints disassembly file to stdout.
    """
    f = open(dis_tmp, 'r')
    print(f.read())
    f.close()

    return

def init_disassembly():
    """ Erases the disassembly.tmp file for writing
    """
    f = open(dis_tmp, 'w')
    f.write("Address       Instruction             Disassembly\n")
    f.write("-----------------------------------------------------\n")
    f.close()

    return


def add_label(ins_address, ins_length, offset):
    """Calculate offset address for given jmp/call instruction and add to list

    Args:
        ins_address (address): Address of jmp/call instruction.
        ins_length (int): Length of instruction in bytes.
        offset (int): Offset location used by jmp/call
    """
    dest = ins_address + ins_length + int(offset, 16)
    label = [ins_address, dest]

    # Prevent duplicates
    if label not in label_list:
        label_list.append(label)

    return


def add_to_disassembly(f, addr, length, disassembly):
    """Adds line of disassembly to disassembly file. Also finds labels.

    Args:
        f (file): File being disassembled.
        address (int): Address of instruction being added
        length (int): Number of bytes in instruction
        disassembly (string): String containing (mnemonic op1, op2)
    """
    global start_time

    if (time() - start_time) >= infinite_threshold:
        answer = ""
        while answer != "y" and answer != "n":
            answer = raw_input("Process has been running for "
                               + str(infinite_threshold) + " seconds. Would you"
                               " like to continue (y/n)? ")
        if answer == "y":
            start_time = time()
        else:
            print("Exiting...")
            exit()

    # Check if instruction requires a label. If so, add it.
    if any(ins in disassembly for ins in label_instructions):
        offset = disassembly.split(' ')[-1] # Offset is last word in string
        add_label(addr, length, offset)

    f_pos = f.tell()    # Save current file position

    f.seek(addr)
    ins_bytes = f.read(length)
    dis_line = "0x" + hex(addr)[2:].zfill(8) + "    " \
               + hexlify(ins_bytes).ljust(10) + "              " \
               + disassembly + "\n"


    if dis_line not in instructions_written:
        f2 = open(dis_tmp, "a")
        f2.write(dis_line)

    f.seek(f_pos)   # Restore file position

    return

def post_process_disassembly(dis_file):
    """Performs various post process on the disassembly.

    Sorts by address, in the case of recursive traversal - Then adds labels.

    Args:
        dis_file (file): Disassembly file
    """
    last_label = "" # Used to prevent duplicate labels being placed when more
                    # than one instruction branch to the same address.

    f = open(dis_file, 'r')
    header = f.readline() + f.readline()
    dis = f.readlines()
    f.close()

    # SORT / REMOVE DUPLICATES
    dis = list(set(dis))
    dis.sort(key=lambda a_line: a_line.split()[0])


    # ADD LABELS
    tmp = ""

    f = open(dis_file, 'w')
    f.write(header)

    for line in dis:
        f.write(tmp)
        tmp = line
        addr = int(line.split(' ')[0][2:], 16)
        for label in label_list:
            if label[1] == addr and label[1] != last_label:
                f.write("\t\t\t   0x" + hex(label[1])[2:].zfill(8) + ":\n")
                last_label = label[1]
            if label[0] == addr:
                tmp = line.rsplit(' ', 1)[0] +" 0x" \
                      + hex(label[1])[2:].zfill(8) + "\n"

    f.write(tmp)
    f.close()

    return


def get_instruction_row(opcode, extension=None):
    """Takes an opcode string and returns its row in the instruction table.

    Args:
        opcode (string): The opcode whose row you want to return
        extension (string): Secondary opcode

    Returns:
        row_index (int): Row index into instruction table of opcode's
        instruction.
        None: Returned if opcode not found.
    """

    for row in instruction_table:
        if row[c_opcode].lower() == opcode.lower():
            if extension == None:
                return instruction_table.index(row)
            elif row[c_rmreg] == extension:
                return instruction_table.index(row)


    return None


def parse_modrm_byte(modrm_byte):
    """ Takes a modrm byte and parses it into the MOD, REG, and R/M fields.

    Args:
        modrmByte (byte): The modrm byte to be parsed

    Returns:
        fieldList (list): The MOD, REG, and R/M fields as a list in that order.
    """

    modrm_byte = hexlify(modrm_byte)

    mod = (int(modrm_byte, 16) >> 6) & 7
    reg = (int(modrm_byte, 16) >> 3) & 7
    rm = int(modrm_byte, 16) & 7

    return [mod, reg, rm]


def parse_sib_byte(sib_byte):
    """ Takes a sib byte and parses it into the SCALE, INDEX, and BASE fields.


    Args:
        sibByte (byte): The sib byte to be parsed

    Returns:
        fieldList (list): The SCALE, INDEX, and BASE fields as a list in that
        order.
    """
    sib_byte = hexlify(sib_byte)

    scale = (int(sib_byte, 16) >> 6) & 7
    index = (int(sib_byte, 16) >> 3) & 7
    base = int(sib_byte, 16) & 7

    return [scale, index, base]


def disassemble(file_obj, start_address, recursive = False):
    """ Perform a Full Disassembly from the start_address.

    Takes a starting address and disassembles it using a Linear Sweep algorithm
    by default, unless "Recursive" is specified - then it will perform a
    Recursive Descent algorithm.

    Args:
        file (file): File to be disassembled.
        start_address (int): The address to begin disassembly at.
        recursive (Boolean): Indicated whether to use recursive or linear
                             disassembly.
    """
    current_address = start_address
    ins_start_addr = start_address
    in_instruction = False
    row = None
    sum_op_flag = False
    tmp_op = None           # Used for setting opcode for summed ops
    f = file_obj

    byte = 1

    # loop over bytes until no more and defer queue is empty
    while byte or defer_queue:

        # If no more bytes left, pop next address off queue
        if recursive and not byte:
            current_address = defer_queue.pop()

        # When not in the middle of parsing instruction...
        if not in_instruction:

            in_instruction = True
            ins_start_addr = current_address
            extension = None    # Extended opcode
            op1 = None

            # Read in byte
            f.seek(current_address)
            current_address += 1
            byte = f.read(1)
            byte = hexlify(byte)

            # 1) Determine Opcode

            # Addition-based opcodes
            if int(byte, 16) >= 0x40 and int(byte, 16) <= 0x47:
                op1 = int(byte, 16) - 0x40
                tmp_op = "40"
                sum_op_flag = True

            elif int(byte, 16) >= 0x48 and int(byte, 16) <= 0x4F:
                op1 = int(byte, 16) - 0x48
                tmp_op = "48"
                sum_op_flag = True

            elif int(byte, 16) >= 0x50 and int(byte, 16) <= 0x57:
                op1 = int(byte, 16) - 0x50
                tmp_op = "50"
                sum_op_flag = True

            elif int(byte, 16) >= 0x58 and int(byte, 16) <= 0x5F:
                op1 = int(byte, 16) - 0x58
                tmp_op = "58"
                sum_op_flag = True

            elif int(byte, 16) >= 0xB8 and int(byte, 16) <= 0xBF:
                op1 = int(byte, 16) - 0xB8
                tmp_op = "B8"
                sum_op_flag = True

            # If opcode is a sum opcode...
            if sum_op_flag:
                row = get_instruction_row(tmp_op)
                if row is None:
                    print("Error: Opcode not found.")
                else:
                    disas = instruction_table[row][c_mnemonic] + " " + \
                            registers[op1]

                    # Handle odd-case addition-based op (mov reg, imm32)
                    if tmp_op == "B8":
                        current_address += 4
                        imm32 = hexlify(f.read(4))
                        imm32 = endian_swap_32(imm32)
                        disas = disas + ", 0x" + imm32

                    add_to_disassembly(f, ins_start_addr,
                                       current_address-ins_start_addr, disas)

                in_instruction = False
                sum_op_flag = False     # Reset flag
            # END ADDITION-BASED OPCODE

            # If 0x0F then it's a two byte opcode. Read another byte.
            elif byte == "0F":
                byte = byte + hexlify(f.read(1))
                current_address += 1

            # Read in extended opcode, if there, and reset file pointer
            elif byte in extended_opcodes:
                extension = hexlify(f.read(1))
                f.seek(f.tell()-1)
                extension = parse_modrm_byte(extension)[c_reg]

            else:
                row = get_instruction_row(byte, extension)
                if row is None:
                    print("Error: Opcode not found. Interpreting as data.")
                    disas = "db '" + byte + "'"
                    add_to_disassembly(f, ins_start_addr, 1, disas)
                    in_instruction = False

                # Check if single byte op
                if ((instruction_table[row][c_rmreg] == "NONE")
                        and (instruction_table[row][c_ins1] == "NONE")
                        and (instruction_table[row][c_ins2] == "NONE")):

                    disas = instruction_table[row][c_mnemonic]
                    add_to_disassembly(f, ins_start_addr, 1, disas)
                    in_instruction = False

                    # Set next byte to end of file if return so that next
                    # address is taken from defer list.
                    if recursive:
                        if "ret" in instruction_table[row][c_mnemonic]:
                            f.seek(0, 2)

        # When parsing instruction...
        elif in_instruction:
            ins = instruction_table[row]
            rm = None      # Used for assigning RM register

            # Handle RM/REG cases

            # RM/REG is NONE
            if ins[c_rmreg] == "NONE":
                if ins[c_ins1] == "EAX":
                    disas = instruction_table[row][c_mnemonic] + " EAX, 0x"
                    if ins[c_ins2] == "imm8":
                        imm8 = hexlify(f.read(1))
                        disas = disas + imm8
                        current_address += 1
                        add_to_disassembly(f, ins_start_addr, 2, disas)

                    elif ins[c_ins2] == "imm32":
                        imm32 = hexlify(f.read(4))
                        imm32 = endian_swap_32(imm32)
                        disas = disas + imm32
                        current_address += 4
                        add_to_disassembly(f, ins_start_addr, 5, disas)

                    else:
                        print("Error: Unsupported immediate at instruction " +
                              ins_start_addr)
                elif ins[c_ins1] == "imm8":
                    disas = instruction_table[row][c_mnemonic] + " "
                    disas = disas + hexlify(f.read(1))
                    current_address += 1
                    add_to_disassembly(f, ins_start_addr, 2, disas)

                elif ins[c_ins1] == "imm16":
                    disas = instruction_table[row][c_mnemonic] + " "
                    disas = disas + endian_swap_32(hexlify(f.read(2)))
                    current_address += 2
                    add_to_disassembly(f, ins_start_addr, 3, disas)

                    # Set next byte to end of file if return so that next
                    # address is taken from defer list.
                    if recursive:
                        if "ret" in instruction_table[row][c_mnemonic]:
                            f.seek(0, 2)

                elif ins[c_ins1] == "imm32":
                    disas = instruction_table[row][c_mnemonic] + " "
                    disas = disas + endian_swap_32(hexlify(f.read(4)))
                    current_address += 4
                    add_to_disassembly(f, ins_start_addr, 5, disas)

                else:
                    print("Error: Unsupported ins1 value " +
                          ins[c_ins1])

                in_instruction = False

            # RM/REG is c32
            elif ins[c_rmreg] == "c32":
                disas = instruction_table[row][c_mnemonic] + " 0x"
                imm32 = endian_swap_32(hexlify(f.read(4)))
                disas = disas + imm32
                current_address += 4
                add_to_disassembly(f, ins_start_addr, 5, disas)

                # Handle instructions for recursive mode.
                if recursive:
                    if instruction_table[row][c_mnemonic] == "call":
                        defer_queue.append(current_address)
                        current_address += htosi(imm32)
                    if instruction_table[row][c_mnemonic] == "jmp":
                        current_address += htosi(imm32)
                    if instruction_table[row][c_mnemonic] == "jnz":
                        defer_queue.append(current_address + htosi(imm32))
                    if instruction_table[row][c_mnemonic] == "jz":
                        defer_queue.append(current_address + htosi(imm32))

                in_instruction = False

            # RM/REG is c8
            elif ins[c_rmreg] == "c8":
                disas = instruction_table[row][c_mnemonic] + " 0x"
                imm8 = hexlify(f.read(1))
                disas = disas + imm8
                current_address += 1
                if ins[c_opcode] == "0F84" or ins[c_opcode] == "0F85":
                    add_to_disassembly(f, ins_start_addr, 3, disas)
                else:
                    add_to_disassembly(f, ins_start_addr, 2, disas)

                # Handle instructions for recursive mode.
                if recursive:
                    if instruction_table[row][c_mnemonic] == "jmp":
                        current_address += htosi(imm8)
                    if instruction_table[row][c_mnemonic] == "jnz":
                        defer_queue.append(current_address + htosi(imm8))
                    if instruction_table[row][c_mnemonic] == "jz":
                        defer_queue.append(current_address + htosi(imm8))

                in_instruction = False

            # RM/REG is r or 0 through 7
            elif (ins[c_rmreg] == "r"
                  or (int(ins[c_rmreg]) >= 0) and (int(ins[c_rmreg]) <= 7)):

                # Add mnemonic to disas string
                disas = instruction_table[row][c_mnemonic] + " "

                # Get and parse the modrm byte
                modrm = parse_modrm_byte(f.read(1))
                current_address += 1

                # modrm mode '11'
                if modrm[c_mod] == reg_access:
                    if ins[c_ins1] == "reg":
                        disas = disas + registers[modrm[c_reg]] + ", "
                        disas = disas + registers[modrm[c_rm]]

                    # Handle extended opcode
                    elif ins[c_rmreg] != "r":
                        disas = disas + registers[modrm[c_rm]]
                        if ins[c_ins2] == "NONE":
                            op2 = ""
                        elif ins[c_ins2] == "imm8":
                            imm8 = hexlify(f.read(1))
                            op2 = ", 0x" + imm8
                            current_address += 1
                        elif ins[c_ins2] == "imm32":
                            imm32 = endian_swap_32(hexlify(f.read(4)))
                            op2 = ", 0x" + imm32
                            current_address += 4
                        else:
                            op2 = ins[c_ins2]

                        disas = disas + op2

                    else:
                        disas = disas + registers[modrm[c_rm]] + ", "
                        disas = disas + registers[modrm[c_reg]]
                    add_to_disassembly(f, ins_start_addr,
                                       (current_address)-ins_start_addr,
                                       disas)
                    in_instruction = False

                # Else, displacement
                else:
                    # Special case for mode '00' and r/m='101'
                    if modrm[c_mod] == mem_access_D0:
                        if modrm[c_rm] == 5:
                            disp32 = endian_swap_32(hexlify(f.read(4)))
                            current_address += 4
                            rm = "0x" + disp32

                    # Check for SIB byte
                    if modrm[c_rm] == 4:
                        sib = parse_sib_byte(f.read(1))
                        current_address += 1
                        rm = (registers[sib[c_base]] + "+"
                              + registers[sib[c_index]] + "*"
                              + scales[sib[c_scale]])

                    # Else, it's just a mem access from a reg
                    else:
                        rm = registers[modrm[c_rm]]

                    # Handle displacements
                    if modrm[c_mod] == mem_access_D1:
                        disp8 = hexlify(f.read(1))
                        current_address += 1
                        rm = "0x" + disp8 + "+" + registers[modrm[c_rm]]

                    if modrm[c_mod] == mem_access_D4:
                        disp32 = endian_swap_32(hexlify(f.read(4)))
                        current_address += 4
                        rm = "0x" + disp32 + "+" + registers[modrm[c_rm]]

                    # Fill in instruction operators
                    if ins[c_ins1] == "reg":
                        disas = disas + registers[modrm[c_reg]] + ", "
                        disas = disas + "[" + rm + "]"

                    # Handle extended opcode
                    elif ins[c_rmreg] != "r":
                        disas = disas + "[" + rm + "], "
                        if ins[c_ins2] == "NONE":
                            op2 = ""
                        elif ins[c_ins2] == "imm8":
                            imm8 = hexlify(f.read(1))
                            op2 = ", 0x" + imm8
                            current_address += 1
                        elif ins[c_ins2] == "imm32":
                            imm32 = endian_swap_32(hexlify(f.read(4)))
                            op2 = ", 0x" + imm32
                            current_address += 4
                        else:
                            op2 = ins[c_ins2]

                        disas = disas + op2
                    else:
                        disas = disas + "[" + rm + "], "
                        disas = disas + registers[modrm[c_reg]]

                    # Add instruction to disassembly
                    add_to_disassembly(f, ins_start_addr,
                                       (current_address)-ins_start_addr,
                                       disas)
                    in_instruction = False

            else:
                print("Error: Unsupported regrm optable value " + ins[c_rmreg])
                in_instruction = False

        # Check if more bytes available by peeking next byte
        byte = f.read(1)
        if byte:
            f.seek(f.tell()-1)


def main():

    # Parse Args
    parser = argparse.ArgumentParser(description='Disassemble an x86 binary. '
                                    'Defaults to Linear Sweep, unless -r flag is'
                                    ' set for recursive descent.')
    parser.add_argument(dest="filename",
                        type=lambda x: is_valid_file(parser, x),
                        help="Binary file to disassemble.", metavar="FILE")
    parser.add_argument('-r', action='store_true',
                        help="Use recursive descent instead of linear sweep.")
    args = parser.parse_args()

    # Get start time for infinite loop testing
    global start_time
    start_time = time()

    # Initialize output file
    init_disassembly()

    # Open given file
    bin_file = open(args.filename, 'rw')

    # Disassemble given gile
    disassemble(bin_file, 0, args.r)

    # Close bin file
    bin_file.close()

    # Cleanup diasassembly
    post_process_disassembly(dis_tmp)

    print_disassembly()

    print("Finished!")
    exit()

if __name__ == "__main__":
    main()
