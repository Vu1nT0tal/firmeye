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
from firmeye.utility import FirmEyeStrMgr, SINK_FUNC
from firmeye.helper import num_to_hexstr, is_func_call
from firmeye.logger import FirmEyeLogger
from firmeye.analysis.static import get_custom_func


class FirmEyeDbgHook(ida_dbg.DBG_Hooks):
    """
    调试器Hook类
    """

    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)

        self.__break_point_hit_count = {}       # 断点触发次数
        self.__break_func_hit_count = {}        # 断点所在函数触发次数

        self.__firmeye_reg_val = {}             # 保存寄存器的值
        for reg in arm_regset.args + (arm_regset.stack, ):
            self.__firmeye_reg_val[reg] = ida_idd.regval_t()

        self.step_dbg = False
    
    def inc_break_func_hit_count(self, func_name):
        if not self.__break_func_hit_count.has_key(func_name):
            self.__break_func_hit_count[func_name] = 0
    
        self.__break_func_hit_count[func_name] += 1

        return self.__break_func_hit_count[func_name]
    
    def inc_break_point_hit_count(self, addr):
        if not self.__break_point_hit_count.has_key(addr):
            self.__break_point_hit_count[addr] = 0
    
        self.__break_point_hit_count[addr] += 1

        return self.__break_point_hit_count[addr]
    
    def get_xdbg_reg_var(self):
        """
        获取寄存器的值
        """
        for reg_t in self.__firmeye_reg_val:
            ida_dbg.get_reg_val(reg_t, self.__firmeye_reg_val[reg_t])
        
        return self.__firmeye_reg_val
    
    def get_args_rule(self, func_name, ea):
        ANY_FUNC = get_custom_func()
        if SINK_FUNC.has_key(func_name):
            args_rule = SINK_FUNC[func_name]['args_rule']
        elif ANY_FUNC.has_key(func_name):
            args_rule = ANY_FUNC[func_name]['args_rule']
        elif ANY_FUNC.has_key(num_to_hexstr(ea)):
            args_rule = ANY_FUNC[num_to_hexstr(ea)]['args_rule']
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
                run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))
            elif arg_t == 'str':
                arg_v = args[str_reg].ival
                if arg_v != 0:
                    str_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
                else:
                    str_t = ''
                run_info[str_reg] = [num_to_hexstr(arg_v), repr(str_t)]
                FirmEyeLogger.console('%s: %s => %s' % (str_reg, num_to_hexstr(arg_v), repr(str_t)))
            elif arg_t == 'fmt':
                arg_v = args[str_reg].ival
                fmt_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
                run_info[str_reg] = [num_to_hexstr(arg_v), repr(fmt_t)]
                FirmEyeLogger.console('%s: %s => %s' % (str_reg, num_to_hexstr(arg_v), repr(fmt_t)))
            else:
                run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))

        # 判断是否包含格式字符串
        if fmt_t != '':
            fmt_list = FirmEyeStrMgr.parse_format_string(str_t)
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
                        str_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
                        run_info[str_reg] = [num_to_hexstr(arg_v), repr(str_t)]
                        FirmEyeLogger.console('%s: %s => %s' % (str_reg, num_to_hexstr(arg_v), repr(str_t)))
                    else:
                        run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                        FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))
            # n>4 寄存器+栈
            else:
                stack_num = args_num - 4
                sp_addr = args[arm_regset.stack].ival
                for jdx in range(4 - idx - 1):
                    str_reg = 'R%s' % (idx+jdx+1)
                    if 's' in fmt_list[jdx]:
                        arg_v = args[str_reg].ival
                        str_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
                        run_info[str_reg] = [num_to_hexstr(arg_v), repr(str_t)]
                        FirmEyeLogger.console('%s: %s => %s' % (str_reg, num_to_hexstr(arg_v), repr(str_t)))
                    else:
                        run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                        FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))

                run_info[arm_regset.stack] = []
                for kdx in range(stack_num):
                    stack_v = ida_bytes.get_wide_dword(sp_addr)
                    if 's' in fmt_list[jdx+kdx+1]:
                        if stack_v == 0:
                            str_t = ''
                        else:
                            str_t = FirmEyeStrMgr.get_string_from_mem(stack_v)
                        run_info[arm_regset.stack].append([num_to_hexstr(sp_addr), num_to_hexstr(stack_v), repr(str_t)])
                        FirmEyeLogger.console('stack: %s - %s => %s' % (num_to_hexstr(sp_addr), num_to_hexstr(stack_v), repr(str_t)))
                    else:
                        run_info[arm_regset.stack].append([num_to_hexstr(sp_addr), num_to_hexstr(stack_v), None])
                        FirmEyeLogger.console('stack: %s - %s' % (num_to_hexstr(sp_addr), num_to_hexstr(stack_v)))
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
                run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))
            elif arg_t == 'str':
                arg_v = args[str_reg].ival
                if arg_v != 0:
                    str_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
                else:
                    str_t = ''
                run_info[str_reg] = [num_to_hexstr(arg_v), repr(str_t)]
                FirmEyeLogger.console('%s: %s => %s' % (str_reg, num_to_hexstr(arg_v), repr(str_t)))
            else:
                run_info[str_reg] = [num_to_hexstr(args[str_reg].ival), None]
                FirmEyeLogger.console('%s: %s' % (str_reg, num_to_hexstr(args[str_reg].ival)))
        
        return run_info

    def get_before_run_info(self, args_rule):
        """
        获取某函数执行前的寄存器信息
        """

        runtime_info = {}
        args = self.get_xdbg_reg_var()

        rv = ida_idd.regval_t()
        ida_dbg.get_reg_val('PC', rv)
        FirmEyeLogger.console('PC: %s' % num_to_hexstr(rv.ival))

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
        FirmEyeLogger.console('PC: %s' % num_to_hexstr(rv.ival))

        arg_v = args[arm_regset.ret].ival
        #str_t = FirmEyeStrMgr.get_string_from_mem(arg_v)
        #runtime_info[arm_regset.ret] = [num_to_hexstr(arg_v), repr(str_t)]
        #FirmEyeLogger.console('ret: %s => %s' % (num_to_hexstr(arg_v), repr(str_t)))
        FirmEyeLogger.console('%s: %s' % (arm_regset.ret, num_to_hexstr(arg_v)))
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
                FirmEyeLogger.console('临时断点%s' % num_to_hexstr(ea))
            else:
                up_func_name_t = ida_funcs.get_func_name(ea)
                func_hit_count = self.inc_break_func_hit_count(up_func_name_t)

                FirmEyeLogger.console(func_name_t + ' - ' + up_func_name_t + '-'*60)
                FirmEyeLogger.console('tid - %d - %d, pointHit: %d, funcHit: %d' %
                                        (tid, time.time(), point_hit_count, func_hit_count))
                FirmEyeLogger.console(('%s - before' + '-'*30) % func_name_t)

                ida_dbg.refresh_debugger_memory()
                before_info = self.get_before_run_info(args_rule)

        elif is_func_call(ida_bytes.prev_head(ea, 0)):
            # 如果当前地址的上一条地址是函数调用（即调用后）

            func_ea = ida_bytes.prev_head(ea, 0)
            func_name = idc.print_operand(func_ea, 0)
            args_rule = self.get_args_rule(func_name, func_ea)

            FirmEyeLogger.console(('%s - after ' + '-'*30) % func_name)

            # ida_dbg.refresh_debugger_memory()
            after_info = self.get_after_run_info(args_rule)

        else:
            FirmEyeLogger.console('临时断点%s' % num_to_hexstr(ea))
        
        # 是否单步调试
        if self.step_dbg == False:
            ida_dbg.continue_process()

        return 0


class FirmEyeDynamicAnalyzer(ida_kernwin.action_handler_t):
    """
    动态分析器
    """

    __xdbg_hook_status = False

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)
        self.firmeye_dbg_hook = FirmEyeDbgHook()

    def get_xdbg_hook_status(self):
        return self.__xdbg_hook_status

    def set_xdbg_hook_status(self):
        self.__xdbg_hook_status = not self.__xdbg_hook_status

    @FirmEyeLogger.reload
    def activate(self, ctx):
        if self.get_xdbg_hook_status():
            FirmEyeLogger.info('关闭调试事件记录')
            self.firmeye_dbg_hook.unhook()
        else:
            FirmEyeLogger.info('启用调试事件记录')

            if ida_kernwin.ask_yn(0, '是否单步调试？') == 1:
                self.firmeye_dbg_hook.step_dbg = True
            else:
                self.firmeye_dbg_hook.step_dbg = False
            self.firmeye_dbg_hook.hook()

        self.set_xdbg_hook_status()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
