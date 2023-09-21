import struct
from dataclasses import dataclass

from .bpf import *

# https://elixir.bootlin.com/linux/v6.5.4/source/kernel/seccomp.c#L275
_ALLOWED_SECCOMP_OPCODES = set([
    BPF_LD | BPF_W | BPF_ABS,
    BPF_LD | BPF_W | BPF_LEN,
    BPF_LDX | BPF_W | BPF_LEN,
    BPF_RET | BPF_K,
    BPF_RET | BPF_A,
    BPF_ALU | BPF_ADD | BPF_K,
    BPF_ALU | BPF_ADD | BPF_X,
    BPF_ALU | BPF_SUB | BPF_K,
    BPF_ALU | BPF_SUB | BPF_X,
    BPF_ALU | BPF_MUL | BPF_K,
    BPF_ALU | BPF_MUL | BPF_X,
    BPF_ALU | BPF_DIV | BPF_K,
    BPF_ALU | BPF_DIV | BPF_X,
    BPF_ALU | BPF_AND | BPF_K,
    BPF_ALU | BPF_AND | BPF_X,
    BPF_ALU | BPF_OR | BPF_K,
    BPF_ALU | BPF_OR | BPF_X,
    BPF_ALU | BPF_XOR | BPF_K,
    BPF_ALU | BPF_XOR | BPF_X,
    BPF_ALU | BPF_LSH | BPF_K,
    BPF_ALU | BPF_LSH | BPF_X,
    BPF_ALU | BPF_RSH | BPF_K,
    BPF_ALU | BPF_RSH | BPF_X,
    BPF_ALU | BPF_NEG,
    BPF_LD | BPF_IMM,
    BPF_LDX | BPF_IMM,
    BPF_MISC | BPF_TAX,
    BPF_MISC | BPF_TXA,
    BPF_LD | BPF_MEM,
    BPF_LDX | BPF_MEM,
    BPF_ST,
    BPF_STX,
    BPF_JMP | BPF_JA,
    BPF_JMP | BPF_JEQ | BPF_K,
    BPF_JMP | BPF_JEQ | BPF_X,
    BPF_JMP | BPF_JGE | BPF_K,
    BPF_JMP | BPF_JGE | BPF_X,
    BPF_JMP | BPF_JGT | BPF_K,
    BPF_JMP | BPF_JGT | BPF_X,
    BPF_JMP | BPF_JSET | BPF_K,
    BPF_JMP | BPF_JSET | BPF_X,
])

@dataclass
class Instruction:
    code: int
    jt: int
    jf: int
    k: int

    def is_valid_seccomp(self):
        # TODO add this check
        # if self.code == BPF_LD | BPF_W | BPF_ABS:
        #     if self.k >= sizeof(struct seccomp_data) or (self.k & 3) != 0:
        #         return False
        return self.code in _ALLOWED_SECCOMP_OPCODES


def disassemble(raw: bytes) -> Instruction | None:
    if len(raw) != 8: return None

    code, jt, jf, k = struct.unpack('<HBBi', raw)
    inst = Instruction(code, jt, jf, k)

    if inst.is_valid_seccomp():
        return inst
    else:
        return None
