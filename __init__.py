from typing import List, Optional, Tuple
from binaryninja import *
from binaryninja.log import log_debug, log_info, log_warn, log_error

from .disassembler import disassemble, Instruction
from .bpf import *

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
        'zero': RegisterInfo('zero', 4), # register stack top, always zero
        '_SP': RegisterInfo('_SP', 4), # unused

        **{ # registers that will form the memory cells
            RegisterName(f'mem_{i}'): RegisterInfo(f'mem_{i}', 4)
            for i in range(MEMORY_CELLS)
        }
    }
    stack_pointer = '_SP'

    reg_stacks = {
        'mem': RegisterStackInfo([f'mem_{i}' for i in range(MEMORY_CELLS)], [], 'zero')
    }

    intrinsics = {
        'return': IntrinsicInfo([IntrinsicInput(Type.int(4), 'ret')], [])
    }

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
            log_warn(f'Unknown instruction at {hex(addr)}')
            return 8

        # initial setup
        if addr == 0:
            il.append(il.set_reg(4, 'A', il.const(4, 0)))
            il.append(il.set_reg(4, 'X', il.const(4, 0)))
            il.append(il.set_reg(4, 'zero', il.const(4, 0)))

        class_ = BPF_CLASS(i.code)
        op = BPF_OP(i.code)
        src = BPF_SRC(i.code)

        if i.code == BPF_RET | BPF_K:
            il.append(il.intrinsic([], 'return', [il.const(4, i.k)]))
            il.append(il.no_ret())

        elif i.code == BPF_RET | BPF_A:
            il.append(il.intrinsic([], 'return', [il.reg(4, 'A')]))
            il.append(il.no_ret())

        elif class_ == BPF_ALU:
            if op == BPF_NEG:
                il.append(il.set_reg(4, 'A', il.neg_expr(4, il.reg(4, 'A'))))
            else:
                value = {
                    BPF_K: il.const(4, i.k),
                    BPF_X: il.reg(4, 'X'),
                }[src]

                aluop = {
                    BPF_ADD: il.add,
                    BPF_SUB: il.sub,
                    BPF_MUL: il.mult,
                    BPF_DIV: il.div_unsigned,
                    BPF_AND: il.and_expr,
                    BPF_OR: il.or_expr,
                    BPF_XOR: il.xor_expr,
                    BPF_LSH: il.shift_left,
                    BPF_RSH: il.logical_shift_right,
                }[op]

                value = aluop(4, il.reg(4, 'A'), value)
                il.append(il.set_reg(4, 'A', value))

        elif i.code == BPF_MISC | BPF_TAX:
            il.append(il.set_reg(4, 'X', il.reg(4, 'A')))

        elif i.code == BPF_MISC | BPF_TXA:
            il.append(il.set_reg(4, 'A', il.reg(4, 'X')))

        elif class_ == BPF_JMP:
            if op == BPF_JA:
                target = addr + i.k * 8 + 8
                il.append(il.jump(il.const_pointer(4, target)))
            else:
                jt = addr + i.jt * 8 + 8
                jf = addr + i.jf * 8 + 8

                value = {
                    BPF_K: il.const(4, i.k),
                    BPF_X: il.reg(4, 'X'),
                }[src]

                if op == BPF_JSET:
                    cmp = il.compare_not_equal(
                        4,
                        il.and_expr(4, il.reg(4, 'A'), value),
                        il.const(4, 0)
                    )
                else:
                    cmp = {
                        BPF_JEQ: il.compare_equal,
                        BPF_JGT: il.compare_unsigned_greater_than,
                        BPF_JGE: il.compare_unsigned_greater_equal,
                    }[op](4, il.reg(4, 'A'), value)

                t = il.get_label_for_address(Architecture['Seccomp'], jt)
                indirect_t = False
                if t is None:
                    indirect_t = True
                    t = LowLevelILLabel()

                f = il.get_label_for_address(Architecture['Seccomp'], jf)
                indirect_f = False
                if f is None:
                    indirect_f = True
                    f = LowLevelILLabel()

                il.append(il.if_expr(cmp, t, f))

                if indirect_t:
                    il.mark_label(t)
                    il.append(il.jump(il.const_pointer(4, jt)))
                if indirect_f:
                    il.mark_label(f)
                    il.append(il.jump(il.const_pointer(4, jf)))

        elif i.code == BPF_LD | BPF_IMM:
            il.append(il.set_reg(4, 'A', il.const(4, i.k)))

        elif i.code == BPF_LDX | BPF_IMM:
            il.append(il.set_reg(4, 'X', il.const(4, i.k)))

        elif i.code == BPF_LD | BPF_MEM:
            il.append(il.set_reg(4, 'A', il.reg_stack_top_relative(4, 'mem', il.const(4, i.k))))

        elif i.code == BPF_LDX | BPF_MEM:
            il.append(il.set_reg(4, 'X', il.reg_stack_top_relative(4, 'mem', il.const(4, i.k))))

        elif i.code == BPF_ST:
            il.append(il.set_reg_stack_top_relative(4, 'mem', il.const(4, i.k), il.reg(4, 'A')))

        elif i.code == BPF_STX:
            il.append(il.set_reg_stack_top_relative(4, 'mem', il.const(4, i.k), il.reg(4, 'X')))

        elif i.code == BPF_LD | BPF_W | BPF_ABS:
            il.append(il.set_reg(4, 'A', il.load(4, il.const_pointer(4, SECCOMP_DATA_BASE + i.k))))

        else:
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

        # Syscall data
        self.add_auto_segment(
            SECCOMP_DATA_BASE, 0x40, 0, 0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentContainsData
        )
        self.add_auto_section('syscall_data', SECCOMP_DATA_BASE, 0x40, SectionSemantics.ReadWriteDataSectionSemantics)

        seccomp_data = [
            'syscall_number',
            'arch',
            'instruction_pointer_lo',
            'instruction_pointer_hi',
            'arg0_lo', 'arg0_hi',
            'arg1_lo', 'arg1_hi',
            'arg2_lo', 'arg2_hi',
            'arg3_lo', 'arg3_hi',
            'arg4_lo', 'arg4_hi',
            'arg5_lo', 'arg5_hi',
        ]
        for i,name in enumerate(seccomp_data):
            self.define_data_var(SECCOMP_DATA_BASE + i*4, Type.int(4), name)

        return True

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        return 0

    def perform_get_address_size(self) -> int:
        return 4

Seccomp.register()
SeccompView.register()
