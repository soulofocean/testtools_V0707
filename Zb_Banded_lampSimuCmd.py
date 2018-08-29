#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-19'
"""
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd,Banded_lamp,Load_zb_ini_file
from basic.BasicProtocol import ZIGBEE
import ConfigParser


class Banded_lampCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Banded_lamp"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)






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
    zigbee_obj = ZIGBEE(port, logger=LOG, savefile=True)
    Load_zb_ini_file(zb_obj=zigbee_obj, loadfile=True)
    zigbee_obj.run_forever()
    zigbee_obj.set_device(eval("Banded_lamp"))
    cmd = Banded_lampCmd(logger=LOG, cprint=cprint)
    cmd.cmdloop()