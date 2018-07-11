#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-11'
"""
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd, BaseWifiSim

# region const variates
rout_addr = ('192.168.10.1', 65381)

class SomatoSensorCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "SomatoSensor"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()

    def help_al_lb(self):
        self.cprint.notice_p("low_battery alarm:al_lb [on/off]")

    def do_al_lb(self,arg):
        self.sim_obj.lb_alarm(arg)

    def help_al_st(self):
        self.cprint.notice_p("status alarm:al_st [on/off]")

    def do_al_st(self,arg):
        self.sim_obj.st_alarm(arg)

    def help_al_rm(self):
        self.cprint.notice_p("removal alarm:al_rm [on/off]")

    def do_al_rm(self,arg):
        self.sim_obj.rm_alarm(arg)



class SomatoSensor(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(SomatoSensor, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                           deviceCategory='somatosensor.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self.al_lbDict = {"alarm_low_battery": "on"}
        self.al_stDict = {"status": "on"}
        self.al_rmDict = {"alarm_removal": "on"}

    def lb_alarm(self,arg):
        self.al_lbDict["alarm_low_battery"] = arg
        msg = self.new_alarm_report(self.al_lbDict)
        self.send_msg(msg)
    def st_alarm(self,arg):
        self.al_stDict["status"] = arg
        msg = self.new_alarm_report(self.al_stDict)
        self.send_msg(msg)
    def rm_alarm(self,arg):
        self.al_rmDict["alarm_removal"] = arg
        msg = self.new_alarm_report(self.al_rmDict)
        self.send_msg(msg)

    def get_event_report(self):
        pass

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"doorsensor.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                pass
            else:
                self.LOG.warn('Unknow msg!')

        if msg['method'] == 'dm_set':

            if msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')


if __name__ == '__main__':
    LOG = MyLogger(os.path.abspath(sys.argv[0]).replace('py', 'log'), clevel=logging.DEBUG,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    SomatoSensorcmd = SomatoSensorCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (SomatoSensorcmd.mac,))
    SomatoSensorcmd.cmdloop()