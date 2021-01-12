# -*- coding: utf-8 -*-

class RegisterSet():
    """
    定义通用寄存器结构
    """

    def __init__(self, pc=None, stack=None, frame=None, flags=None,
            flagsr=None, common=tuple(), args=tuple(), ret=None):
        self.pc = pc
        self.common = common
        self.stack = stack
        self.frame = frame
        self.flags = flags
        self.flagsr = flagsr
        self.args = args
        self.all = list(filter(None, common + (pc, stack, frame, flagsr)))
        self.ret = ret

    def __len__(self):
        return len(self.all)

    def __iter__(self):
        for reg in self.all:
            yield reg

x86_flags = ('ID', 'VIP', 'VIF', 'AC', 'VM', 'RF', 'NT', 'IOPL', 'OF',
             'DF', 'IF', 'TF', 'SF', 'ZF', 'AF', 'PF', 'CF')

x86_regset = RegisterSet(
    pc     = 'EIP',
    frame  = 'EBP',
    stack  = 'ESP',
    flags  = x86_flags,
    flagsr = 'EFL',
    common = ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI'),
    ret    = 'EAX'
)

x64_regset = RegisterSet(
    pc     = 'RIP',
    frame  = 'RBP',
    stack  = 'RSP',
    flags  = x86_flags,
    flagsr = 'EFL',
    args   = ('RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9'),
    common = ('RAX', 'RBX', 'RCX', 'RDX', 'RDI', 'RSI',
              'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15'),
    ret    = 'RAX'
)

arm_regset = RegisterSet(
    pc     = 'PC',
    stack  = 'SP',
    flags  = ('N', 'Z', 'C', 'V', 'Q', 'IT2', 'J', 'GE', 'IT', 'E',
              'A', 'I', 'F', 'T', 'MODE'),
    flagsr = 'PSR',
    args   = ('R0', 'R1', 'R2', 'R3'),
    common = tuple('R%i' % i for i in range(13)) + ('LR',),
    ret    = 'R0'
)

aarch64_regset = RegisterSet(
    pc     = 'PC',
    stack  = 'SP',
    flagsr = 'PSR',
    common = tuple('X%i' % i for i in range(31)) + ('LR',),
    args   = ('X0', 'X1', 'X2', 'X3'),
    ret    = 'X0'
)

mips_regset = RegisterSet(
    pc     = 'PC',
    frame  = 'FP',
    stack  = 'SP',
    common = ('V0', 'V1', 'A0', 'A1', 'A2', 'A3', 'T0', 'T1', 'T2', 'T3', 'T4', 'T5',
              'T6', 'T7', 'T8', 'T9', 'S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7'),
    args   = ('A0', 'A1', 'A2', 'A3'),
    ret    = 'A0'
)
