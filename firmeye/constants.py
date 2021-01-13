# -*- coding: utf-8 -*-

PLUGIN_NAME = "Firmeye"
PLUGIN_HOTKEY = "Ctrl+F1"
PLUGIN_COMMENT = "Firmeye: an auxiliary tool for iot vulnerability hunter."
PLUGIN_HELP = '''
#############################  FIRMEYE TOOLKITS ##############################
#                                                                            #
#               an auxiliary tool for iot vulnerability hunter               #
#                                                                            #
# ------------------------------- HOT KEAY --------------------------------- #
#                                                                            #
#    Ctrl+F1             show this help                                      #
#                                                                            #
# --------------------------- STATIC  ANALYZER ----------------------------- #
#                                                                            #
#    Ctrl+Shift+s        main menu                                           #
#                                                                            #
# --------------------------- DYNAMIC ANALYZER ----------------------------- #
#                                                                            #
#    Ctrl+Shift+d        enable/disable debug hook                           #
#                                                                            #
# --------------------------- REVERSE ASSISTANT ---------------------------- #
#                                                                            #
#    Ctrl+Shift+x        reverse assist tools                                #
#                                                                            #
# --------------------------- FUNCTIONAL TEST ------------------------------ #
#                                                                            #
#    Ctrl+Shift+q        functional test                                     #
#                                                                            #
##############################################################################
'''

AUTHOR = "Chao Yang"
XDBG_VERSION = "v0.1.1"
XDBG_IDA_DEP_VERSION = "IDA PRO 7.5, Python3"
BANNER_MSG = "Firmeye %s - %s" % (XDBG_VERSION, XDBG_IDA_DEP_VERSION)
