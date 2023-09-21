from enum import IntEnum

# https://elixir.bootlin.com/linux/v6.5.4/source/include/uapi/linux/filter.h
# https://elixir.bootlin.com/linux/v6.5.4/source/include/uapi/linux/bpf_common.h

BPF_CLASS = lambda x: x & 0x07
BPF_SIZE = lambda x: x & 0x18
BPF_MODE = lambda x: x & 0xE0
BPF_OP = lambda x: x & 0xF0
BPF_SRC = lambda x: x & 0x08

BPF_LD = 0x00
BPF_LDX = 0x01
BPF_ST = 0x02
BPF_STX = 0x03
BPF_ALU = 0x04
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_MISC = 0x07

BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10

BPF_IMM = 0x00
BPF_ABS = 0x20
BPF_IND = 0x40
BPF_MEM = 0x60
BPF_LEN = 0x80
BPF_MSH = 0xA0

BPF_ADD = 0x00
BPF_SUB = 0x10
BPF_MUL = 0x20
BPF_DIV = 0x30
BPF_OR = 0x40
BPF_AND = 0x50
BPF_LSH = 0x60
BPF_RSH = 0x70
BPF_NEG = 0x80
BPF_MOD = 0x90
BPF_XOR = 0xA0

BPF_JA = 0x00
BPF_JEQ = 0x10
BPF_JGT = 0x20
BPF_JGE = 0x30
BPF_JSET = 0x40

BPF_K = 0x00
BPF_X = 0x08
BPF_A = 0x10

BPF_TAX = 0x00
BPF_TXA = 0x80
