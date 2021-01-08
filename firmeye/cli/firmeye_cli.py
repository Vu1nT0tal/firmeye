# -*- coding: utf-8 -*-  

from firmeye.utility import *
from firmeye.analysis.static import *

def analysis():
    f = open('analyze_result.txt', 'w+')
    result = []
    mgr_t = FirmEyeSinkFuncMgr()

    for func_name, xref_list in mgr_t.gen_sink_func_xref():
        tag = SINK_FUNC[func_name]['tag']
        if tag == PRINTF:
            items = printf_func_analysis(func_name, xref_list)
            result += build_result(items)
        elif tag == STRING:
            items = str_func_analysis(func_name, xref_list)
            result += build_result(items)
        elif tag == SCANF:
            items = scanf_func_analysis(func_name, xref_list)
            result += build_result(items)
        elif tag == SYSTEM:
            items = system_func_analysis(func_name, xref_list)
            result += build_result(items)
        elif tag == MEMORY:
            items = mem_func_analysis(func_name, xref_list)
            result += build_result(items)
        else:
            continue

    f.writelines(result)
    f.close

def build_result(items):
    lines = []
    for item in items:
        data = [str(item.vuln), item.name, num_to_hexstr(item.ea)]
        for x in [item.addr1, item.addr2]:
            if x != None:
                data.append(num_to_hexstr(x))
            else:
                continue
        for x in [item.str1, item.str2, item.other1]:
            if x != None:
                data.append(repr(x))
            else:
                continue
        data.append('\n')
        lines.append('\t'.join(data))
    return lines

if __name__ == "__main__":
    analysis()
    if "DO_EXIT" in os.environ:
        idc.qexit(1)
