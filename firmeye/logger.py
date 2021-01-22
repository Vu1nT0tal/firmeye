# -*- coding: utf-8 -*-

import os
import time
from functools import wraps

import ida_nalt
import ida_kernwin

from firmeye.config import DEBUG


class FELogger():
    """
    日志、调试配置管理类
    """

    enable_dbg = DEBUG
    log_path = ''
    log_fd = None
    time_cost = {}

    @classmethod
    def get_dbg_mode(cls):
        return cls.enable_dbg

    @classmethod
    def enable_debug(cls):
        cls.enable_dbg = True

    @classmethod
    def disable_debug(cls):
        cls.enable_dbg = False

    @classmethod
    def reload(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if cls.get_dbg_mode():
                cur_workpath = os.getcwd()
                log_filename = '%s.xdbg' % ida_nalt.get_root_filename()
                log_filepath = os.path.join(cur_workpath, log_filename)
                cls.log_path = log_filepath
                if cls.log_fd:
                    cls.log_fd.close()
                    cls.log_fd = None
                cls.log_fd = open(cls.log_path, 'a')
            return func(*args, **kwargs)
        return wrapper

    @classmethod
    def log_time(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            s_time = time.perf_counter()
            ret_t = func(*args, **kwargs)
            e_time = time.perf_counter()
            if not func.__name__ in cls.time_cost:
                cls.time_cost[func.__name__] = 0
            cls.time_cost[func.__name__] += e_time - s_time
            return ret_t
        return wrapper

    @classmethod
    def show_time_cost(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ret_t = func(*args, **kwargs)
            for func_name in cls.time_cost:
                cls.info('%s: %f seconds' % (func_name, cls.time_cost[func_name]))
            return ret_t
        return wrapper

    @classmethod
    def log(cls, level, msg, debug):
        if level == 'console':
            msg_t = '%s\n' % msg
        else:
            msg_t = '[%s] %s\n' % (level, msg)

        if cls.log_fd:
            if cls.enable_dbg or debug:
                cls.log_fd.write(msg_t)
                cls.log_fd.flush()

        ida_kernwin.msg(msg_t)
        if level == 'warn' or level == 'erro':
            ida_kernwin.warning(msg_t)

    @classmethod
    def console(cls, msg, debug=False):
        cls.log(level='console', msg=msg, debug=debug)

    @classmethod
    def info(cls, msg, debug=False):
        cls.log(level='info', msg=msg, debug=debug)

    @classmethod
    def warn(cls, msg, debug=False):
        cls.log(level='warn', msg=msg, debug=debug)

    @classmethod
    def erro(cls, msg, debug=False):
        cls.log(level='erro', msg=msg, debug=debug)
