from typing import List, Optional, Tuple
from binaryninja import *
from binaryninja.log import log_debug, log_info, log_warn, log_error

from .disassembler import disassemble, Instruction
from .bpf import *

# binja renders accesses to 0 as *nullptr, shift the memory up to avoid it
MEMORY_BASE = 0x100000
MEMORY_CELLS = 16
SECCOMP_DATA_BASE = 0x200000

class Seccomp(Architecture):
    name = "Seccomp"
    address_size = 4
    default_int_size = 1
    instr_alignment = 8
    max_instr_length = 8
    regs = {
        'A': RegisterInfo('A', 4),
        'X': RegisterInfo('X', 4),
        '_SP': RegisterInfo('_SP', 4), # unused
        'zero': RegisterInfo('zero', 4), # unused
        **{
            RegisterName(f'mem_{i}'): RegisterInfo(f'mem_{i}', 4)
            for i in range(MEMORY_CELLS)
        }
    } # type: ignore
    stack_pointer = '_SP'
    reg_stacks = {
        'mem': RegisterStackInfo([f'mem_{i}' for i in range(MEMORY_CELLS)], [], 'zero')
    } # type: ignore

    def get_instruction_info(self, data: bytes, addr: int) -> InstructionInfo | None:
        i = disassemble(data)
        if i is None: return None

        BT = BranchType
        info = InstructionInfo()
        info.length = 8

        if BPF_CLASS(i.code) not in [BPF_JMP, BPF_RET]:
            return info

        if BPF_CLASS(i.code) == BPF_RET:
            info.add_branch(BT.FunctionReturn)
        else:
            op = BPF_OP(i.code)
            if op == BPF_JA:
                target = addr + i.k * 8 + 8
                info.add_branch(BT.UnconditionalBranch, target)
            else:
                jt = addr + i.jt * 8 + 8
                jf = addr + i.jf * 8 + 8
                info.add_branch(BT.TrueBranch, jt)
                info.add_branch(BT.FalseBranch, jf)

        return info

    def get_instruction_text(self, data: bytes, addr: int) -> Tuple[List[InstructionTextToken], int] | None:
        i = disassemble(data)

        T = InstructionTextToken
        TT = InstructionTextTokenType

        sp = T(TT.OperandSeparatorToken, ' ')
        eq = T(TT.TextToken, '=')
        A = T(TT.RegisterToken, 'A')
        X = T(TT.RegisterToken, 'X')
        def mem(idx):
            return [
                T(TT.DataSymbolToken, 'mem'),
                T(TT.BeginMemoryOperandToken, '['),
                T(TT.ArrayIndexToken, str(idx), idx),
                T(TT.EndMemoryOperandToken, ']')
            ]

        if i is None:
            return [T(TT.TextToken, 'invalid')], 8

        fixed = {
            BPF_LD | BPF_W | BPF_ABS: [
                A, sp, eq, sp,
                T(TT.DataSymbolToken, 'seccomp_data'),
                T(TT.BeginMemoryOperandToken, '['),
                T(TT.ArrayIndexToken, hex(i.k), i.k),
                T(TT.EndMemoryOperandToken, ']')
            ],
            BPF_LD | BPF_W | BPF_LEN: [A, sp, eq, sp, T(TT.TextToken, 'sizeof(struct seccomp_data)')],
            BPF_LDX | BPF_W | BPF_LEN: [X, sp, eq, sp, T(TT.TextToken, 'sizeof(struct seccomp_data)')],

            BPF_RET | BPF_K: [T(TT.KeywordToken, 'return'), sp, T(TT.IntegerToken, hex(i.k), i.k)],
            BPF_RET | BPF_A: [T(TT.KeywordToken, 'return'), sp, A],
            BPF_LD | BPF_IMM: [A, sp, eq, sp, T(TT.IntegerToken, hex(i.k), i.k)],
            BPF_LDX | BPF_IMM: [X, sp, eq, sp, T(TT.IntegerToken, hex(i.k), i.k)],
            BPF_MISC | BPF_TAX: [X, sp, eq, sp, A],
            BPF_MISC | BPF_TXA: [A, sp, eq, sp, X],
            BPF_LD | BPF_MEM: [A, sp, eq, sp] + mem(i.k),
            BPF_LDX | BPF_MEM: [X, sp, eq, sp] + mem(i.k),
            BPF_ST: mem(i.k) + [sp, eq, sp, A],
            BPF_STX: mem(i.k) + [sp, eq, sp, X],
            BPF_ALU | BPF_NEG: [A, sp, eq, sp, T(TT.TextToken, '-'), A],
        }

        out = []
        if i.code in fixed:
            out = fixed[i.code]
        elif BPF_CLASS(i.code) == BPF_ALU:
            # BPF_NEG is handled above
            aluop = {
                BPF_ADD: '+=',
                BPF_SUB: '-=',
                BPF_MUL: '*=',
                BPF_DIV: '/=',
                BPF_AND: '&=',
                BPF_OR: '|=',
                BPF_XOR: '^=',
                BPF_LSH: '<<=',
                BPF_RSH: '>>=',
            }[BPF_OP(i.code)]

            src = {
                BPF_X: X,
                BPF_K: T(TT.IntegerToken, hex(i.k), i.k),
            }[BPF_SRC(i.code)]

            out = [A, sp, T(TT.TextToken, aluop), sp, src]

        elif BPF_CLASS(i.code) == BPF_JMP:
            op = BPF_OP(i.code)

            if op == BPF_JA:
                target = addr + i.k * 8 + 8
                out = [T(TT.TextToken, 'goto'), sp, T(TT.AddressDisplayToken, hex(target), target)]

            else:
                jt = addr + i.jt * 8 + 8
                jf = addr + i.jf * 8 + 8

                cmp = {
                    BPF_JEQ: '==',
                    BPF_JGT: '>',
                    BPF_JGE: '>=',
                    BPF_JSET: '&',
                }[BPF_OP(i.code)]

                src = {
                    BPF_X: X,
                    BPF_K: T(TT.IntegerToken, hex(i.k), i.k),
                }[BPF_SRC(i.code)]

                out = [
                    T(TT.TextToken, '('), A, sp, T(TT.TextToken, cmp), sp, src, T(TT.TextToken, ')'),
                    sp, T(TT.TextToken, '?'), sp,
                    T(TT.TextToken, 'goto'), sp, T(TT.AddressDisplayToken, hex(jt), jt),
                    sp, T(TT.TextToken, ':'), sp,
                    T(TT.TextToken, 'goto'), sp, T(TT.AddressDisplayToken, hex(jf), jf),
                ]

        else:
            out = [
                T(TT.BraceToken, '{'), sp,
                T(TT.TextToken, 'CODE'), sp, T(TT.IntegerToken, f'{i.code:#04x}', i.code), sp,
                T(TT.TextToken, 'JT'), sp, T(TT.IntegerToken, f'{i.jt:#02x}', i.jt), sp,
                T(TT.TextToken, 'JF'), sp, T(TT.IntegerToken, f'{i.jf:#02x}', i.jf), sp,
                T(TT.TextToken, 'K'), sp, T(TT.IntegerToken, f'{i.k:#x}', i.k), sp,
                T(TT.BraceToken, '}'),
            ]

        return out, 8

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> int:
        i = disassemble(data)
        if i is None:
            il.append(il.unimplemented())
            return 8

        il.append(il.unimplemented())
        return 8

class SeccompView(BinaryView):
    name = 'Seccomp'
    long_name = name

    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        return data.length <= 4096*8 and data.length % 8 == 0

    def __init__(self, data: BinaryView):
        super().__init__(file_metadata=data.file, parent_view=data)
        self.platform = Architecture['Seccomp'].standalone_platform
        self.data = data

    def init(self) -> bool:
        # Code
        self.add_auto_segment(
            0, self.data.length, 0, self.data.length,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable | SegmentFlag.SegmentContainsCode
        )
        self.add_auto_section('text', 0, self.data.length, SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_entry_point(0)
        self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, 0, 'filter'))

        # Data
        self.add_auto_segment(
            MEMORY_BASE, MEMORY_CELLS * 4, 0, 0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
        )
        self.add_auto_section('memory', MEMORY_BASE, MEMORY_CELLS * 4, SectionSemantics.ReadWriteDataSectionSemantics)

        # Syscall data
        # TODO: length and contents
        self.add_auto_segment(
            SECCOMP_DATA_BASE, 0x100, 0, 0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentDenyWrite | SegmentFlag.SegmentContainsData
        )
        self.add_auto_section('data', SECCOMP_DATA_BASE, 0x100, SectionSemantics.ReadOnlyDataSectionSemantics)

        return True

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return 0

    def perform_get_address_size(self) -> int:
        return 4

Seccomp.register()
SeccompView.register()
