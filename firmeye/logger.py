# -*- coding: utf-8 -*-

import os
import time
from functools import wraps
import idaapi
from firmeye.config import DEBUG
from firmeye.utility import str_gbk_to_utf8, str_utf8_to_gbk

class FirmEyeLogger():
    """
    日志、调试配置管理类
    """

    __enable_dbg = DEBUG
    __log_path = ''
    __log_fd = None
    __time_cost = {}

    @classmethod
    def get_dbg_mode(cls):
        return cls.__enable_dbg

    @classmethod
    def enable_debug(cls):
        cls.__enable_dbg = True

    @classmethod
    def disable_debug(cls):
        cls.__enable_dbg = False

    @classmethod
    def reload(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if cls.get_dbg_mode():
                cur_workpath_t = str_gbk_to_utf8(os.getcwd())
                log_filename_t = '%s.xdbg' % idaapi.get_input_file_path().split('\\')[-1]
                log_filepath_t = os.path.join(cur_workpath_t, log_filename_t)
                cls.__log_path = str_utf8_to_gbk(log_filepath_t)
                if cls.__log_fd:
                    cls.__log_fd.close()
                    cls.__log_fd = None
                cls.__log_fd = open(cls.__log_path, 'a')
            return func(*args, **kwargs)
        return wrapper

    @classmethod
    def log_time(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            s_time = time.clock()
            ret_t = func(*args, **kwargs)
            e_time = time.clock()
            if not cls.__time_cost.has_key(func.__name__):
                cls.__time_cost[func.__name__] = 0
            cls.__time_cost[func.__name__] += e_time - s_time
            return ret_t
        return wrapper

    @classmethod
    def show_time_cost(cls, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ret_t = func(*args, **kwargs)
            for func_name in cls.__time_cost:
                cls.info('%s: %f seconds' % (func_name, cls.__time_cost[func_name]))
            return ret_t
        return wrapper

    @classmethod
    def log(cls, level, msg, debug):
        if level == 'console':
            msg_t = '%s\n' % msg
        else:
            msg_t = '[%s] %s\n' % (level, msg)
        
        if cls.__log_fd:
            if cls.__enable_dbg or debug:
                cls.__log_fd.write(msg_t)
                cls.__log_fd.flush()
        
        idaapi.msg(msg_t)
        if level == 'warn' or level == 'erro':
            idaapi.warning(msg_t)

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
