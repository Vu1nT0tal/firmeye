# -*- coding: utf-8 -*-
# https://github.com/patois/HexraysToolbox
# commit: 1ca5e93ed65d8dfa91cc25b8a42452113a1f0eb4

import ida_hexrays as hx
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
import idc
import ida_idaapi

from firmeye.logger import FELogger

SCRIPT_NAME = "[toolbox]"

class query_result_t():
    def __init__(self, cfunc=None, i=None):
        if isinstance(cfunc, hx.cfuncptr_t):
            self.entry = cfunc.entry_ea
        elif isinstance(cfunc, int):
            self.entry = cfunc
        else:
            self.entry = BADADDR
        if isinstance(i, (hx.cexpr_t, hx.cinsn_t)):
            self.ea = i.ea if not isinstance(cfunc, hx.cfuncptr_t) else self.find_closest_address(cfunc, i)
            self.v = ida_lines.tag_remove(i.print1(None))
        elif isinstance(i, tuple):
            self.ea, self.v = i
        else:
            self.ea = ida_idaapi.BADADDR
            self.v = "<undefined>"

    def find_closest_address(self, cfunc, i):
        parent = i
        while parent:
            if parent and parent.ea != BADADDR:
                return parent.ea
            parent = cfunc.body.find_parent_of(parent)
        return BADADDR

    def __str__(self):
        return "[%x] %x: \"%s\"" % (self.entry, self.ea, self.v)


def find_item(ea, q, parents=False, flags=0):
    """在函数伪代码的 AST 中搜索 item

    ea: 函数内任意地址
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    parents: False -> 丢弃 cexpr_t 父节点
             True  -> 维护 citem_t 父节点

    return: query_result_t 对象列表
    """

    f = ida_funcs.get_func(ea)
    if f:
        cfunc = None
        hf = hx.hexrays_failure_t()
        try:
            cfunc = hx.decompile(f, hf, flags)
        except Exception as e:
            print("%s %x: unable to decompile: '%s'" % (SCRIPT_NAME, ea, hf))
            print("\t (%s)" % e)
            return list()

        if cfunc:
            return find_child_item(cfunc, cfunc.body, q, parents)
    return list()

def find_child_item(cfunc, i, q, parents=False):
    """find child item in cfunc_t starting at citem_t i

    cfunc: cfunc_t
    i: citem_t
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值

    return: query_result_t 对象列表
    """

    class citem_finder_t(hx.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hx.ctree_visitor_t.__init__(self,
                hx.CV_PARENTS if parents else hx.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            if self.query(self.cfunc, i):
                self.found.append(query_result_t(self.cfunc, i))
            return 0

        def visit_insn(self, i):
            return self.process(i)

        def visit_expr(self, e):
            return self.process(e)

    if cfunc:
        itfinder = citem_finder_t(cfunc, q, parents)
        itfinder.apply_to(i, None)
        return itfinder.found
    return list()

def find_expr(ea, q, parents=False, flags=0):
    """在函数伪代码的 AST 中搜索表达式

    ea: 函数内任意地址
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    parents: False -> 丢弃 cexpr_t 父节点
             True  -> 维护 citem_t 父节点

    return: query_result_t 对象列表
    """

    f = ida_funcs.get_func(ea)
    if f:
        cfunc = None
        hf = hx.hexrays_failure_t()
        try:
            cfunc = hx.decompile(f, hf, flags)
        except Exception as e:
            print("%s %x: unable to decompile: '%s'" % (SCRIPT_NAME, ea, hf))
            print("\t (%s)" % e)
            return list()

        if cfunc:
            return find_child_expr(cfunc, cfunc.body, q, parents)
    return list()

def find_child_expr(cfunc, e, q, parents=False):
    """find child expression in cfunc_t starting at cexpr_t e

    cfunc: cfunc_t
    e: cexpr_t
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值

    return: query_result_t 对象列表
    """

    class expr_finder_t(hx.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hx.ctree_visitor_t.__init__(self,
                hx.CV_PARENTS if parents else hx.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def visit_expr(self, e):
            if self.query(self.cfunc, e):
                self.found.append(query_result_t(self.cfunc, e))
            return 0

    if cfunc:
        expfinder = expr_finder_t(cfunc, q, parents)
        expfinder.apply_to_exprs(e, None)
        return expfinder.found
    return list()

def exec_query(q, ea_list, query_full, parents=False, flags=0):
    """在地址列表上执行 find_item 或 find_item

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: query_result_t 对象列表
    """

    find_elem = find_item if query_full else find_expr
    result = list()
    for ea in ea_list:
        result += find_elem(ea, q, parents=parents, flags=flags)
    return result

def query_db(q, query_full=True, do_print=False):
    """在 IDB 上执行 query

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: query_result_t 对象列表
    """

    return query(q, ea_list=idautils.Functions(), query_full=query_full, do_print=do_print)

def query(q, ea_list=None, query_full=True, do_print=False):
    """在地址列表上执行 exec_query，可打印结果

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: query_result_t 对象列表
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]
    r = list()
    try:
        r = exec_query(q, ea_list, query_full)
        if do_print:
            print("<query> done! %d unique hits." % len(r))
            for e in r:
                print(e)
    except Exception as exc:
        print("<query> error:", exc)
    return r


class ic_t(ida_kernwin.Choose):
    """citem_t 选择器

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值或者 query_result_t 对象列表
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）
    """
    window_title = "Hexrays Toolbox"

    def __init__(self,
            q=None,
            ea_list=None,
            query_full=True,
            flags=ida_kernwin.CH_RESTORE | ida_kernwin.CH_QFLT,
            title=None,
            width=None,
            height=None,
            embedded=False,
            modal=False):

        _title = ""
        i = 0
        idx = ""
        pfx = ""
        exists = True
        while exists:
            idx = chr(ord('A')+i%26)
            _title = "%s-%s%s" % (ic_t.window_title, pfx, idx)
            if title:
                _title += ": %s" % title
            exists = (ida_kernwin.find_widget(_title) != None)
            i += 1
            pfx += "" if i % 26 else "A"

        ida_kernwin.Choose.__init__(self,
            _title,
            [ ["函数", 20 | ida_kernwin.CHCOL_FNAME],
              ["地址", 10 | ida_kernwin.CHCOL_EA],
              ["输出", 80 | ida_kernwin.CHCOL_PLAIN]],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)

        if ea_list is None:
            ea_list =[ida_kernwin.get_screen_ea()]
        if callable(q):
            self.items = exec_query(q, ea_list, query_full)
        elif isinstance(q, list):
            self.items = q
        else:
            self.items = list()
        self.Show()

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        item_ea = self.items[n].ea
        func_ea = self.items[n].entry
        ea = func_ea if item_ea == BADADDR else item_ea
        ida_kernwin.jumpto(ea)

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        return len(self.items)

    def append(self, data):
        if not isinstance(data, query_result_t):
            return False
        self.items.append(data)
        self.Refresh()
        return True

    def set_data(self, data):
        self.items = data
        self.Refresh()

    def get_data(self):
        return self.items

    def _make_choser_entry(self, n):
        return ["%s" % idc.get_func_off_str(self.items[n].entry),
                "%016x" % self.items[n].ea if __EA64__ else "%08x" % self.items[n].ea,
                self.items[n].v]


class FECodePatternForm(ida_kernwin.Form):

    def __init__(self):
        ida_kernwin.Form.__init__(self, """STARTITEM 0
Reverse Assistant
TODO：
<##TODO:{btn_todo}>
""", {
    'btn_todo': ida_kernwin.Form.ButtonInput(self.btn_todo),
})

    def btn_todo(self, code=0):
        pass


class FECodePattern(ida_kernwin.action_handler_t):
    """
    在伪代码中做代码模式匹配
    """

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def show_menu(self):
        main = FECodePatternForm()
        main.Compile()
        main.Execute()

    @FELogger.reload
    def activate(self, ctx):
        self.show_menu()

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


"""
def find_memcpy():
    "find calls to memcpy() where the 'n' argument is signed"

    query = lambda cf, e: (e.op is cot_call and
        e.x.op is cot_obj and
        'memcpy' in get_name(e.x.obj_ea) and
        len(e.a) == 3 and
        e.a[2].op is cot_var and
        cf.lvars[e.a[2].v.idx].tif.is_signed())

    return tb.exec_query(query, Functions(), False)

def find_sprintf():
    "find calls to sprintf() where the format string argument contains '%s'"

    func_name = 'sprintf'

    query = lambda cfunc, e: (e.op is cot_call and
        e.x.op is cot_obj and
        func_name in get_name(e.x.obj_ea) and
        len(e.a) >= 2 and
        e.a[1].op is cot_obj and
        is_strlit(get_flags(e.a[1].obj_ea)) and
        b'%s' in get_strlit_contents(e.a[1].obj_ea, -1, 0, STRCONV_ESCAPE))

    ea_malloc = get_name_ea_simple(func_name)
    ea_set = set([f.start_ea for f in [get_func(xref.frm) for xref in XrefsTo(ea_malloc, XREF_FAR)] if f])
    
    return tb.exec_query(query, ea_set, False)

def find_malloc():
    "calls to malloc() with a size argument that is anything but a variable or an immediate number."

    func_name = 'malloc'

    query = lambda cf, e: (e.op is cot_call and 
        e.x.op is cot_obj and
        get_name(e.x.obj_ea) == func_name and
        len(e.a) == 1 and
        e.a[0].op not in [cot_num, cot_var])

    ea_malloc = get_name_ea_simple(func_name)
    ea_set = set([f.start_ea for f in [get_func(xref.frm) for xref in XrefsTo(ea_malloc, XREF_FAR)] if f])
    
    return tb.exec_query(query, ea_set, False)
"""
