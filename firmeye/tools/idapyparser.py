# -*- coding: utf-8 -*-  

import os
import inspect
import idaapi


class FileViewForm(idaapi.Form):
    def __init__(self, title, content):
        super(FileViewForm, self).__init__(
"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
%s
<##content##:{btn_content}>""" % title, {
    'btn_content': idaapi.Form.MultiLineTextControl(text=content,
    flags=idaapi.textctrl_info_t.TXTF_READONLY | idaapi.textctrl_info_t.TXTF_FIXEDFONT)
})


class DocViewForm(idaapi.Form):
    def __init__(self, title, content):
        super(DocViewForm, self).__init__(
"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
%s
<##content##:{btn_content}>""" % title, {
    'btn_content': idaapi.Form.MultiLineTextControl(text=content,
    flags=idaapi.textctrl_info_t.TXTF_READONLY | idaapi.textctrl_info_t.TXTF_FIXEDFONT)
})


class ChooseData():
    icon_ids = {"str": 80, "int": 8, "long": 8, "class": 89, "function": 81,
                "method": 90, "builtin_function_or_method": 90}

    def __init__(self, mod_name, sym_name, file_name):
        self.mod_name = mod_name
        self.sym_name = sym_name
        self.file_name = file_name
        self.doc_str = ""
        self.sym_type = ""
        self.sym_value = ""
        self.line_num = ""

    def get_icon(self):
        return self.icon_ids[self.sym_type]


class FirmEyeIDAParserChoose(idaapi.Chooes):
    """
    IDAParser窗口选择器
    """

    def __init__(self, title):
        cols = [["模块", 10 | idaapi.Choose.CHCOL_PLAIN],
                ["符号", 20 | idaapi.Choose.CHCOL_PLAIN],
                ["文档", 10 | idaapi.Choose.CHCOL_PLAIN],
                ["类型", 10 | idaapi.Choose.CHCOL_PLAIN],
                ["取值", 10 | idaapi.Choose.CHCOL_HEX],
                ["行号", 10 | idaapi.Choose.CHCOL_DEC]]
        
        super(FirmEyeIDAParserChoose, self).__init__(
            title=title, cols=cols, flags=idaapi.Choose.CH_QFLT | idaapi.Choose.CH_NOIDB
        )

        self.items = []
        self.icon = 0
        self.build_items()

    def build_items(self):
        unknown_sym = {}
        pydir = idaapi.idadir("python")
        for mod_name in os.listdir(pydir):
            if mod_name.endswith(".py"):
                mod_name, _ = os.path.splitext(mod_name)
                if mod_name in ["init", "idaapi"]:
                    continue
                else:
                    mod = __import__(mod_name)
                    file_name = mod.__file__
                    for sym_name, obj in inspect.getmembers(mod):
                        data = ChooseData(mod_name, sym_name, file_name)
                        if inspect.isfunction(obj):
                            data.sym_type = "function"
                            data.line_num = "%d" % obj.func_code.co_firstlineno
                            data.doc_str = inspect.getdoc(obj)
                        elif inspect.isclass(obj):
                            data.sym_type = "class"
                            data.doc_str = inspect.getdoc(obj)
                        elif inspect.ismethod(obj):
                            data.sym_type = "method"
                            data.line_num = "%d" % obj.im_func.func_code.co_firstlineno
                            data.doc_str = inspect.getdoc(obj)
                        elif type(obj) == int:
                            data.sym_type = "int"
                            data.sym_value = "0x%x" % obj
                        elif type(obj) == long:
                            data.sym_type = "long"
                            data.sym_value = "0x%x" % obj
                        elif type(obj) == str:
                            data.sym_type = "str"
                            data.sym_value = obj
                        elif inspect.isbuiltin(obj):
                            data.sym_type = "builtin_function_or_method"
                            data.doc_str = inspect.getdoc(obj)
                        elif inspect.ismodule(obj):
                            continue
                        else:
                            if not unknown_sym.has_key(sym_name):
                                unknown_sym[sym_name] = type(obj)
                            else:
                                pass
                            continue
                        self.items.append(data)
            else:
                continue

        for sym in unknown_sym:
            print "未知符号：%s - %s" % (unknown_sym[sym], sym)

    def OnGetLine(self, n):
        d = self.items[n]
        data = [d.mod_name, d.sym_name, "%s"%d.doc_str, d.sym_type, d.sym_value, d.line_num]
        return data
    
    def OnGetIcon(self, n):
        return self.items[n].get_icon()
    
    def OnGetSize(self):
        return len(self.items)
    
    def OnSelectLine(self, n):
        data = self.items[n]
        title = data.mod_name + "-" + data.sym_name
        if not data.doc_str:
            print "文档不存在：%s" % data.sym_name
        else:
            form = DocViewForm(title, data.doc_str)
            form.modal = False
            form.openform_flags = idaapi.PluginForm.WOPN_TAB
            form, _ = form.Compile()
            form.Open()
        return (idaapi.Choose.NOTHING_CHANGED, )

    def OnEditLine(self, n):
        fn = self.items[n].file_name
        if fn.endswith(".pyc"):
            fn = fn[:-1]
        else:
            pass
        with open(fn) as f:
            title = os.path.basename(fn)
            form = FileViewForm(title, f.read())
            form.modal = False
            form.openform_flags = idaapi.PluginForm.WOPN_TAB
            form, _ = form.Compile()
            form.Open()
        return (idaapi.Choose.NOTHING_CHANGED, )

