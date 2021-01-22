# -*- coding: utf-8 -*-

import time

import idc
import ida_dbg
import ida_idd
import ida_kernwin
import ida_bytes
import ida_funcs
import idautils

from firmeye.regs import arm_regset
from firmeye.utility import FEStrMgr, SINK_FUNC
from firmeye.helper import hexstr, is_func_call
from firmeye.logger import FELogger
from firmeye.analysis.static import get_custom_func


class FEDbgHook(ida_dbg.DBG_Hooks):
    """
    调试器Hook类
    """

    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)

        self.bp_hit_count = {}          # 断点触发次数
        self.bf_hit_count = {}          # 断点所在函数触发次数

        self.reg_val = {}               # 保存寄存器的值
        for reg in arm_regset.args + (arm_regset.stack, ):
            self.reg_val[reg] = ida_idd.regval_t()

        self.step_dbg = False

    def inc_break_func_hit_count(self, func_name):
        if not func_name in self.bf_hit_count:
            self.bf_hit_count[func_name] = 0

        self.bf_hit_count[func_name] += 1

        return self.bf_hit_count[func_name]

    def inc_break_point_hit_count(self, addr):
        if not addr in self.bp_hit_count:
            self.bp_hit_count[addr] = 0

        self.bp_hit_count[addr] += 1

        return self.bp_hit_count[addr]

    def get_xdbg_reg_var(self):
        """
        获取寄存器的值
        """
        for reg_t in self.reg_val:
            ida_dbg.get_reg_val(reg_t, self.reg_val[reg_t])

        return self.reg_val

    def get_args_rule(self, func_name, ea):
        CUSTOM_FUNC = get_custom_func()
        if func_name in SINK_FUNC:
            args_rule = SINK_FUNC[func_name]['args_rule']
        elif func_name in CUSTOM_FUNC:
            args_rule = CUSTOM_FUNC[func_name]['args_rule']
        elif hexstr(ea) in CUSTOM_FUNC:
            args_rule = CUSTOM_FUNC[hexstr(ea)]['args_rule']
        else:
            args_rule = False
        return args_rule

    def var_len_args_run_info(self, args_rule, args):
        """
        获取变长参数函数的寄存器信息
        """

        run_info = {}
        fmt_t = ''

        for idx in range(len(args_rule) - 1):
            str_reg = 'R%s' % idx
            arg_t = args_rule[idx]
            if arg_t == 'none':      # 跳过无关参数
                continue
            elif arg_t == 'int':
                run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))
            elif arg_t == 'str':
                arg_v = args[str_reg].ival
                if arg_v != 0:
                    str_t = FEStrMgr.get_string_from_mem(arg_v)
                else:
                    str_t = ''
                run_info[str_reg] = [hexstr(arg_v), repr(str_t)]
                FELogger.console('%s: %s => %s' % (str_reg, hexstr(arg_v), repr(str_t)))
            elif arg_t == 'fmt':
                arg_v = args[str_reg].ival
                fmt_t = FEStrMgr.get_string_from_mem(arg_v)
                run_info[str_reg] = [hexstr(arg_v), repr(fmt_t)]
                FELogger.console('%s: %s => %s' % (str_reg, hexstr(arg_v), repr(fmt_t)))
            else:
                run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))

        # 判断是否包含格式字符串
        if fmt_t != '':
            fmt_list = FEStrMgr.parse_format_string(str_t)
            args_num = len(fmt_list) + idx + 1
            # 判断变长参数总个数
            if idx+1 == args_num:
                pass
            # n<=4 寄存器
            elif idx+1 < args_num and args_num <= 4:
                for jdx in range(len(fmt_list)):
                    str_reg = 'R%s' % (idx+jdx+1)
                    if 's' in fmt_list[jdx]:
                        arg_v = args[str_reg].ival
                        str_t = FEStrMgr.get_string_from_mem(arg_v)
                        run_info[str_reg] = [hexstr(arg_v), repr(str_t)]
                        FELogger.console('%s: %s => %s' % (str_reg, hexstr(arg_v), repr(str_t)))
                    else:
                        run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                        FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))
            # n>4 寄存器+栈
            else:
                stack_num = args_num - 4
                sp_addr = args[arm_regset.stack].ival
                for jdx in range(4 - idx - 1):
                    str_reg = 'R%s' % (idx+jdx+1)
                    if 's' in fmt_list[jdx]:
                        arg_v = args[str_reg].ival
                        str_t = FEStrMgr.get_string_from_mem(arg_v)
                        run_info[str_reg] = [hexstr(arg_v), repr(str_t)]
                        FELogger.console('%s: %s => %s' % (str_reg, hexstr(arg_v), repr(str_t)))
                    else:
                        run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                        FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))

                run_info[arm_regset.stack] = []
                for kdx in range(stack_num):
                    stack_v = ida_bytes.get_wide_dword(sp_addr)
                    if 's' in fmt_list[jdx+kdx+1]:
                        if stack_v == 0:
                            str_t = ''
                        else:
                            str_t = FEStrMgr.get_string_from_mem(stack_v)
                        run_info[arm_regset.stack].append([hexstr(sp_addr), hexstr(stack_v), repr(str_t)])
                        FELogger.console('stack: %s - %s => %s' % (hexstr(sp_addr), hexstr(stack_v), repr(str_t)))
                    else:
                        run_info[arm_regset.stack].append([hexstr(sp_addr), hexstr(stack_v), None])
                        FELogger.console('stack: %s - %s' % (hexstr(sp_addr), hexstr(stack_v)))
                    sp_addr += 4
        else:
            pass

        return run_info

    def fix_len_args_run_info(self, args_rule, args):
        """
        获取定长参数函数的寄存器信息
        """

        run_info = {}

        for idx in range(len(args_rule)):
            str_reg = 'R%s' % idx
            arg_t = args_rule[idx]
            if arg_t == 'none':     # 跳过无关的参数
                continue
            elif arg_t == 'int':
                run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))
            elif arg_t == 'str':
                arg_v = args[str_reg].ival
                if arg_v != 0:
                    str_t = FEStrMgr.get_string_from_mem(arg_v)
                else:
                    str_t = ''
                run_info[str_reg] = [hexstr(arg_v), repr(str_t)]
                FELogger.console('%s: %s => %s' % (str_reg, hexstr(arg_v), repr(str_t)))
            else:
                run_info[str_reg] = [hexstr(args[str_reg].ival), None]
                FELogger.console('%s: %s' % (str_reg, hexstr(args[str_reg].ival)))

        return run_info

    def get_before_run_info(self, args_rule):
        """
        获取某函数执行前的寄存器信息
        """

        runtime_info = {}
        args = self.get_xdbg_reg_var()

        rv = ida_idd.regval_t()
        ida_dbg.get_reg_val('PC', rv)
        FELogger.console('PC: %s' % hexstr(rv.ival))

        # 判断是否包含变长参数
        if args_rule[-1] == '...':
            runtime_info = self.var_len_args_run_info(args_rule, args)
        elif args_rule[-1] == 'va_list':
            # TODO 支持va_list参数解析，暂时同“...”
            runtime_info = self.var_len_args_run_info(args_rule, args)
        else:
            runtime_info = self.fix_len_args_run_info(args_rule, args)

        return runtime_info

    def get_after_run_info(self, args_rule):
        """
        获取某函数执行后的返回值
        # TODO 添加参数的变化
        """

        runtime_info = {}
        args = self.get_xdbg_reg_var()

        rv = ida_idd.regval_t()
        ida_dbg.get_reg_val('PC', rv)
        FELogger.console('PC: %s' % hexstr(rv.ival))

        arg_v = args[arm_regset.ret].ival
        #str_t = FEStrMgr.get_string_from_mem(arg_v)
        #runtime_info[arm_regset.ret] = [hexstr(arg_v), repr(str_t)]
        #FELogger.console('ret: %s => %s' % (hexstr(arg_v), repr(str_t)))
        FELogger.console('%s: %s' % (arm_regset.ret, hexstr(arg_v)))
        return runtime_info

    def dbg_bpt(self, tid, ea):
        """
        触发断点时的处理函数
        """

        func_name_t = idc.print_operand(ea, 0)
        point_hit_count = self.inc_break_point_hit_count(ea)

        if is_func_call(ea):
            # 如果当前地址是函数调用（即调用前）

            args_rule = self.get_args_rule(func_name_t, ea)
            if args_rule == False:
                FELogger.console('临时断点%s' % hexstr(ea))
            else:
                up_func_name = ida_funcs.get_func_name(ea)
                func_hit_count = self.inc_break_func_hit_count(up_func_name)

                FELogger.console(func_name_t + ' - ' + up_func_name + '-'*60)
                FELogger.console('tid - %d - %d, pointHit: %d, funcHit: %d' %
                                        (tid, time.time(), point_hit_count, func_hit_count))
                FELogger.console(('%s - before' + '-'*30) % func_name_t)

                ida_dbg.refresh_debugger_memory()
                before_info = self.get_before_run_info(args_rule)

        elif is_func_call(ida_bytes.prev_head(ea, 0)):
            # 如果当前地址的上一条地址是函数调用（即调用后）

            func_ea = ida_bytes.prev_head(ea, 0)
            func_name = idc.print_operand(func_ea, 0)
            args_rule = self.get_args_rule(func_name, func_ea)

            FELogger.console(('%s - after ' + '-'*30) % func_name)

            # ida_dbg.refresh_debugger_memory()
            after_info = self.get_after_run_info(args_rule)

        else:
            FELogger.console('临时断点%s' % hexstr(ea))

        # 是否单步调试
        if self.step_dbg == False:
            ida_dbg.continue_process()

        return 0


class FEDynamicAnalyzer(ida_kernwin.action_handler_t):
    """
    动态分析器
    """

    hook_status = False

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.dbg_hook = FEDbgHook()

    def get_xdbg_hook_status(self):
        return self.hook_status

    def set_xdbg_hook_status(self):
        self.hook_status = not self.hook_status

    @FELogger.reload
    def activate(self, ctx):
        if self.get_xdbg_hook_status():
            FELogger.info('关闭调试事件记录')
            self.dbg_hook.unhook()
        else:
            FELogger.info('启用调试事件记录')

            if ida_kernwin.ask_yn(0, '是否单步调试？') == 1:
                self.dbg_hook.step_dbg = True
            else:
                self.dbg_hook.step_dbg = False
            self.dbg_hook.hook()

        self.set_xdbg_hook_status()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
