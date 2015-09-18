"""
    Defines various constants used through the disassembler.
"""

"""
    Registers
"""
registers = ['EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI']
EAX = 0
ECX = 1
EDX = 2
EBX = 3
ESP = 4
EBP = 5
ESI = 6
EDI = 7

"""
    MODR/M Modes
"""
memAccess_D0 = 0
memAccess_D1 = 1
memAccces_D4 = 2
regAccess = 3


"""
    SIB Scale Bits
"""
scale1 = 0
scale2 = 1
scale4 = 2
scale8 = 3


"""
    instruction table
    Loads list from csv into 2d table.
    Columns: mnemonic, opcode, rmreg, ins1, ins2
"""
instruction_table = []
mnemonic = 0
opcode = 1
rmreg = 2
ins1 = 3
ins2 = 4
with open('instructions_csv.txt') as data_file:
   for line in data_file:
      instruction_table.append(line.strip().split(','))
