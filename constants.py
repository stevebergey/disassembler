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
    MODR/M
"""
mem_access_D0 = 0
mem_access_D1 = 1
mem_access_D4 = 2
reg_access = 3

c_mod = 0
c_reg = 1
c_rm = 2


"""
    SIB
"""
c_scale = 0
c_index = 1
c_base = 2

scales = ['1','2','4','8']


"""
    instruction table
    Loads list from csv into 2d table.
    Columns: mnemonic, opcode, rmreg, ins1, ins2
"""
instruction_table = []
c_mnemonic = 0
c_opcode = 1
c_rmreg = 2
c_ins1 = 3
c_ins2 = 4
with open('instructions_csv.txt') as data_file:
   for line in data_file:
      instruction_table.append(line.strip().split(','))


"""
    Extended Opcode List
"""
extended_opcodes = ['81', '83', '8F', 'C1', 'D1', 'D3', 'F7', 'FF']

"""
    Instructions requiring labels
"""
label_instructions = ['jmp', 'jz', 'jnz', 'call']