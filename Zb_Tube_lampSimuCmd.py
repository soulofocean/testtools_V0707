#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-19'
"""
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd,Tube_lamp
from basic.BasicProtocol import ZIGBEE


class Tube_lampCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Tube_lamp"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)






if __name__ == '__main__':
    LOG = MyLogger("%s.log" % (os.path.basename(sys.argv[0]).split(".")[0],), clevel=logging.INFO,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    zigbee_obj = ZIGBEE('COM4', logger=LOG)
    zigbee_obj.run_forever()
    zigbee_obj.set_device(eval("Tube_lamp"))
    cmd = Tube_lampCmd(logger=LOG, cprint=cprint)
    cmd.cmdloop()