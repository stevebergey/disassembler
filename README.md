# Python x86 Disassembler

The Python x86 Disassembler was created for a Reverse Engineering class project. It supports a limited set of instructions, as seen below. It also contains support for both Linear Sweep and Recursive Descent algorithms. Linear Sweep is chosen by default, unless the '-r' flag is given from the command line.

Disassembly starts at offset 0 in the given file. Headers are currently unsupported.

If an unknown opcode is encountered, it will be treated as data and disassembly will continue.

### Supported Instructions
The following instructions are supported, inclduing RM/REG and SIB bytes. 

not, call, or, cmp, pop, dec, push, idiv, repne  cmpsd, imu, ret, ret, inc, jmp, sal, jz, jnz, sar, lea, sbb, mov, shr, movsd, test, mul, xor, neg          

### Example

You need Gulp installed globally:

```sh
$ disassemble.py -h
usage: disassemble.py [-h] [-r] FILE

Disassemble an x86 binary. Defaults to Linear Sweep, unless -r flag is set for
recursive descent.

positional arguments:
  FILE        Binary file to disassemble.

optional arguments:
  -h, --help  show this help message and exit
  -r          Use recursive descent instead of linear sweep.

$ disassembly.py test.bin
Address       Instruction             Disassembly
-----------------------------------------------------
0x00000000    55                      push EBP
0x00000001    31e5                    xor EBP, ESP
0x00000003    52                      push EDX
0x00000004    e802000000              call 0x0000000b
0x00000009    eb05                    jmp 0x00000010
			                  0x0000000b:
0x0000000b    89148b                  mov [EBX+ECX*4], EDX
0x0000000e    40                      inc EAX
0x0000000f    c3                      retn
			                  0x00000010:
0x00000010    8b411e                  mov EAX, [0x1e+ECX]
0x00000013    c3                      retn
```
where the original disassembly was:
```
[BITS 32]

section .text

	push ebp
	xor  ebp, esp
	push edx
	call example
	jmp end
	example:
	mov [ecx*4 + ebx], edx
	inc eax
	retn
	end:
	mov eax, [ecx+30]
	retn
```




