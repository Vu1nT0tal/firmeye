# -*- coding: utf-8 -*-

import os

DEBUG = True    # 配置DEBUG模式

GHIDRA_PATH = 'E:\\ghidra_9.0.4'
GHIDRA_HEADLESS_PATH = os.path.join(GHIDRA_PATH, "support", "analyzeHeadless.bat")

FUNC_TAG = {
    'PRINTF': 0,
    'STRING': 1,
    'MEMORY': 2,
    'SCANF' : 3,
    'SYSTEM': 4,
}

SINK_FUNC = {
    'printf': {     # int printf(const char *format, ...);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R0'],
            }
        ]
    },
    'sprintf': {     # int sprintf(char *str, const char *format, ...);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['str', 'fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', '...'],
            }
        ]
    },
    'snprintf': {     # int snprintf(char *str, size_t size, const char *format, ...);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['str', 'int', 'fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R2'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', 'R2', '...'],
            }
        ]
    },
    'fprintf': {     # int fprintf(FILE *stream, const char *format, ...);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['dword', 'fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'dprintf': {     # int dprintf(int fd, const char *format, ...);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['int', 'fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'vprintf': {     # int vprintf(const char *format, va_list ap);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R0'],
            }
        ]
    },
    'vfprintf': {     # int vfprintf(FILE *stream, const char *format, va_list ap);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['dword', 'fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'vdprintf': {     # int vdprintf(int fd, const char *format, va_list ap);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['int', 'fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'vsprintf': {     # int vsprintf(char *str, const char *format, va_list ap);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['str', 'fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'vsnprintf': {     # int vsnprintf(char *str, size_t size, const char *format, va_list ap);
        'tag': FUNC_TAG['PRINTF'],
        'args_rule': ['str', 'int', 'fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R2'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', 'R2'],
            }
        ]
    },

    'scanf': {     # int scanf(const char *format, ...);
        'tag': FUNC_TAG['SCANF'],
        'args_rule': ['fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R0'],
            }
        ]
    },
    'sscanf': {     # int sscanf(const char *str, const char *format, ...);
        'tag': FUNC_TAG['SCANF'],
        'args_rule': ['str', 'fmt', '...'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', '...'],
            }
        ]
    },
    'vscanf': {     # int vscanf(const char *format, va_list ap);
        'tag': FUNC_TAG['SCANF'],
        'args_rule': ['fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R0'],
            }
        ]
    },
    'vsscanf': {     # int vsscanf(const char *str, const char *format, va_list ap);
        'tag': FUNC_TAG['SCANF'],
        'args_rule': ['str', 'fmt', 'va_list'],
        'vuln_rule': [
            {
                'vuln_type': 'format_string',
                'vuln_regs': ['R1'],
            },
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },

    'realpath': {     # char *realpath(const char *path, char *resolved_path);
        'tag': '',
        'args_rule': ['str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R0'],
            }
        ]
    },

    'strtrns': {    # char *strtrns (const char *str, const char *old, const char *new, char *result);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str', 'str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R0'],
            }
        ]
    },
    'strecpy': {    # char *strecpy(char *output, const char *input, const char *exceptions);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'streadd': {    # char *streadd(char *output, const char *input, const char *exceptions);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'strncat': {    # char *strncat(char *dest, const char *src, size_t n);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str', 'int'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', 'R2'],
            }
        ]
    },
    'strcat': {    # char *strcat(char *dest, const char *src);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },
    'strncpy': {    # char *strncpy(char *dest, const char *src, size_t n);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str', 'int'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', 'R2'],
            }
        ]
    },
    'strcpy': {    # char *strcpy(char *dest, const char *src);
        'tag': FUNC_TAG['STRING'],
        'args_rule': ['str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1'],
            }
        ]
    },

    'memcpy': {    # void *memcpy(void *dest, const void *src, size_t n);
        'tag': FUNC_TAG['MEMORY'],
        'args_rule': ['str', 'str', 'int'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R1', 'R2'],
            }
        ]
    },

    'popen': {    # FILE *popen(const char *command, const char *type);
        'tag': '',
        'args_rule': ['str', 'str'],
        'vuln_rule': [
            {
                'vuln_type': 'command_injection',
                'vuln_regs': ['R0'],
            }
        ]
    },

    'system': {    # int system(const char *command);
        'tag': FUNC_TAG['SYSTEM'],
        'args_rule': ['str'],
        'vuln_rule': [
            {
                'vuln_type': 'command_injection',
                'vuln_regs': ['R0'],
            }
        ]
    },

    'doSystemCmd': {    # int system(const char *command);
        'tag': FUNC_TAG['SYSTEM'],
        'args_rule': ['str'],
        'vuln_rule': [
            {
                'vuln_type': 'command_injection',
                'vuln_regs': ['R0'],
            }
        ]
    },

    'gets': {    # char *gets(char *s);
        'tag': '',
        'args_rule': ['str'],
        'vuln_rule': [
            {
                'vuln_type': 'stack_buffer_overflow',
                'vuln_regs': ['R0'],
            }
        ]
    },
}

INST_LIST = {
    'load': [       # 加载存储指令
        'LDR', 'LDR.W', 'LDRB', 'LDRB.W', 'LDRD', 'LDRH', 'LDRD.W', 'LDRHI', 'LDRHIB', 'LDRH.W',
        'LDREQ', 'LDREQSB', 'LDRNE', 'LDRNEB', 'LDRLT', 'LDRLS', 'LDRLE', 'LDRGT', 'LDRGE', 'LDRSB', 'LDRSB.W', 'LDRSH', 'LDRSH.W', 'LDRCC', 'LDRCS', 'LDREQB.W',
        'VLDR'
    ],
    'move': [       # 数据传送指令
        'MOV', 'MOV.W', 'MOVS', 'MOVCS', 'MOVCS.W', 'MOVCC', 'MOVEQ', 'MOVNE', 'MOVLT', 'MOVLS', 'MOVLE', 'MOVGT', 'MOVGE', 'MOVGE.W', 'MOVHI', 'MOVHI.W', 'MOVT', 'MOVW', 'MOVT.W', 'MOVTGT.W', 'MOVTLE.W',
        'VMOV', 'MVN',
        'VCVT.F64.F32',
        'REV', 'REV.W', 'CLZ'
    ],
    'arithmetic': [ # 运算指令
        'ADD', 'ADDS', 'ADDCS', 'ADDCC', 'ADDEQ', 'ADDEQ.W', 'ADDNE', 'ADDNE.W', 'ADDLT', 'ADDLT.W', 'ADDLS', 'ADDLE', 'ADDGT', 'ADDGE', 'ADDHI', 'ADD.W', 'ADDW',
        'ADC',
        'SUB', 'SUBS', 'SUBS.W', 'SUB.W', 'SUBGT.W', 'SUBCC', 'SUBCS', 'SUBLE', 'SUBLT', 'SUBLS', 'SUBEQ', 'SUBNE',
        'MUL', 'MULS', 'MUL.W', 'MLA.W', 'MLS.W',
        'SDIV', 'UDIV',
        'RSB', 'RSBNE', 'RSBNE.W', 'RSBHI', 'RSBGT', 'RSB.W', 'RSBCS', 'RSBCC', 'LSL.W', 'LSL', 'LSLS', 'LSRS', 'ASR', 'ASRS',
        'AND', 'ANDS', 'ANDS.W', 'ORR', 'ORRS', 'ORR.W', 'ORRLE', 'EOR', 'BIC',
        'UXTH', 'UXTH.W', 'UBFX.W', 'UBFX', 'UXTB',
        'SXTB', 'SXTH',
        'MLA', 'MLAEQ', 'MLANE', 'MLS', 'MUL',
    ],
    'load_multi': [ # 块数据传送指令
        'LDMFD', 'LDMEQFD', 'LDMEQIB', 'LDMDB', 'LDMDB.W', 'LDMIA', 'LDMIA.W', 'LDMIB', 'LDMLEFD'
    ],
    'other': [      # 其他指令
        'STR', 'STR.W', 'STRB', 'STRB.W', 'STREQ', 'STREQB', 'STREQ.W', 'STRNE', 'STRNEB', 'STRLE', 'STRLS', 'STRH.W', 'STRGT', 'STRH', 'STRHI', 'STRGE', 'STRGEH', 'STRLT',
        'CMP', 'CMP.W', 'CMPNE', 'CMPGT', 'CMPEQ', 'CMPLS', 'CMPNE.W', 'CMPCS', 'CMN', 'CMN.W', 'CBZ', 'CBNZ', 'STMEA', 'STMEA.W', 'STMFD', 'PUSH.W', 'PUSH', 'BLX', 'TST'
    ]
}
