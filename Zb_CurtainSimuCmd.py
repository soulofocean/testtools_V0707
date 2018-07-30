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
import ConfigParser


class CurtainCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Curtain"
        self.keylist = None
        self.watchlist = None
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

    def help_showlist(self):
        self.cprint.notice_p("show current devicelist info: showlist")

    def do_showlist(self, arg=None):
        self.keylist=[]
        self.watchlist = []
        for k in zigbee_obj.devices.keys():
            self.keylist.append(k)
            self.watchlist.append("0x%s" % binascii.hexlify(k))
        self.cprint.notice_p(self.watchlist)

    def help_sd(self):
        self.cprint.notice_p("set current device index,basic on showlist: sd [showlistindex]")
    def do_sd(self, arg):
        args = arg.split()
        if (len(args) != 1 or not args[0].isdigit() or self.watchlist ==None or int(args[0]) >= len(self.keylist)):
            self.help_sd()
        else:
            self.device_addr = self.keylist[int(arg)]






if __name__ == '__main__':
    cf = ConfigParser.ConfigParser()
    cf.read('zigbee_devices.conf')
    port = cf.get('Common', 'port')
    cl_level = eval(cf.get('Common', 'cl_level'))
    fl_level = eval(cf.get('Common', 'fl_level'))
    rm_log = eval(cf.get('Common', 'rm_log'))
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log')
    if rm_log and os.path.isfile(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=cl_level, flevel=fl_level)
    cprint = cprint(__name__)
    zigbee_obj = ZIGBEE(port, logger=LOG)
    zigbee_obj.run_forever()
    zigbee_obj.set_device(eval("Curtain"))
    cmd = CurtainCmd(logger=LOG,cprint=cprint)
    cmd.cmdloop()