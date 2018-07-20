#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-13'
"""
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd,Curtain
from basic.BasicProtocol import ZIGBEE


class CurtainCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Curtain"
        self.device_addr = None
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)

    def help_show(self):
        self.cprint.notice_p("show current device info: show")
        if(self.device_addr == None):
            self.cprint.notice_p("current device is None! use showlist to get addrList")

    def do_show(self, arg=None):
        if(self.device_addr==None):
            self.help_show()
        else:
            print zigbee_obj.devices[self.device_addr].__dict__

    def do_showlist(self, arg=None):
        print zigbee_obj.devices.keys()

    def do_sd(self, arg):
        if(arg in zigbee_obj.devices):
            self.device_addr = arg
        else:
            print ('arg: %s not in devices' % (arg,))






if __name__ == '__main__':
    LOG = MyLogger("%s.log" % (os.path.basename(sys.argv[0]).split(".")[0],), clevel=logging.INFO,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    zigbee_obj = ZIGBEE('COM4', logger=LOG)
    zigbee_obj.run_forever()
    zigbee_obj.set_device(eval("Curtain"))
    cmd = CurtainCmd(logger=LOG,cprint=cprint)
    cmd.cmdloop()