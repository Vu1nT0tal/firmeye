# -*- coding: utf-8 -*-
# https://github.com/patois/HexraysToolbox

import ida_hexrays as hr
import ida_bytes
import idautils
import ida_kernwin
import ida_lines
import ida_funcs
import idc

from firmeye.logger import FELogger


class tb_result_t():
    def __init__(self, i):
        self.ea = i.ea
        self.v = ida_lines.tag_remove(i.print1(None))

    def __str__(self):
        return "%x: %s" % (self.ea, self.v)


def find_item(ea, q, parents=False):
    """在函数伪代码的 AST 中搜索 item

    ea: 函数内任意地址
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    parents: False -> 丢弃 cexpr_t 父节点
             True  -> 维护 citem_t 父节点

    return: tb_result_t 对象列表
    """

    try:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = hr.decompile(f)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        return find_child_item(cfunc, cfunc.body, q, parents)
    return list()

def find_child_item(cfunc, i, q, parents=False):
    """find child item in cfunc_t starting at citem_t i

    cfunc: cfunc_t
    i: citem_t
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值

    return: tb_result_t 对象列表
    """

    class citem_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def process(self, i):
            if self.query(self.cfunc, i):
                self.found.append(tb_result_t(i))
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

def find_expr(ea, q, parents=False):
    """在函数伪代码的 AST 中搜索表达式

    ea: 函数内任意地址
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    parents: False -> 丢弃 cexpr_t 父节点
             True  -> 维护 citem_t 父节点

    return: tb_result_t 对象列表
    """

    try:
        f = ida_funcs.get_func(ea)
        if f:
            cfunc = hr.decompile(f)
    except:
        print("%x: unable to decompile." % ea)
        return list()

    if cfunc:
        return find_child_expr(cfunc, cfunc.body, q, parents)
    return list()

def find_child_expr(cfunc, e, q, parents=False):
    """find child expression in cfunc_t starting at cexpr_t e

    cfunc: cfunc_t
    e: cexpr_t
    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值

    return: tb_result_t 对象列表
    """

    class expr_finder_t(hr.ctree_visitor_t):
        def __init__(self, cfunc, q, parents):
            hr.ctree_visitor_t.__init__(self,
                hr.CV_PARENTS if parents else hr.CV_FAST)

            self.cfunc = cfunc
            self.query = q
            self.found = list()
            return

        def visit_expr(self, e):
            if self.query(self.cfunc, e):
                self.found.append(tb_result_t(e))
            return 0

    if cfunc:
        expfinder = expr_finder_t(cfunc, q, parents)
        expfinder.apply_to_exprs(e, None)
        return expfinder.found
    return list()

def exec_query(q, ea_list, query_full):
    """在地址列表上执行 find_item 或 find_item

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: tb_result_t 对象列表
    """

    find_elem = find_item if query_full else find_expr
    result = list()
    for ea in ea_list:
        result += [e for e in find_elem(ea, q)]
    return result

def query_db(q, query_full=True, do_print=False):
    """在 IDB 上执行 query

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: tb_result_t 对象列表
    """

    return query(q, ea_list=idautils.Functions(), query_full=query_full, do_print=do_print)

def query(q, ea_list=None, query_full=True, do_print=False):
    """在地址列表上执行 exec_query，可打印结果

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）

    return: tb_result_t 对象列表
    """

    if not ea_list:
        ea_list = [ida_kernwin.get_screen_ea()]
    r = list()
    try:
        r = exec_query(q, ea_list, query_full)
        if do_print:
            print("<query> done! %d unique hits." % len(r))
            for e in r:
                print("%x: %s" % (e.ea, e.v))
    except Exception as exc:
        print("<query> error:", exc)
    return r


class ic_t(ida_kernwin.Choose):
    """citem_t 选择器

    q: lambda/function: f(cfunc_t, citem_t) 返回布尔值或者 tb_result_t 对象列表
    ea_list: 地址列表
    query_full: False -> 仅搜索 cexpr_t
                True  -> 搜索 citem_t（包括 cexpr_t 和 cinsn_t）
    """

    def __init__(self, q, ea_list=None, query_full=True,
            flags=ida_kernwin.CH_RESTORE | ida_kernwin.CH_QFLT,
            width=None, height=None, embedded=False, modal=False):
        ida_kernwin.Choose.__init__(self,
            "Hexrays Toolbox",
            [ ["地址", 10 | ida_kernwin.CHCOL_EA],
              ["函数", 20 | ida_kernwin.CHCOL_FNAME],
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
        ida_kernwin.jumpto(self.items[n].ea)

    def OnGetLine(self, n):
        return self._make_choser_entry(n)

    def OnGetSize(self):
        return len(self.items)

    """
    def append(self, data):
        self.items.append(data)
        self.Refresh()
        return
    """
    def set_data(self, data):
        self.items = data
        self.Refresh()

    def _make_choser_entry(self, n):
        return ["%08x" % self.items[n].ea,
                "%s" % idc.get_func_off_str(self.items[n].ea),
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
