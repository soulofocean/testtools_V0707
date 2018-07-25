#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-11'
"""
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd, BaseWifiSim
if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')
coding = sys.getfilesystemencoding()
# region const variates
import ConfigParser
cf = ConfigParser.ConfigParser()
cf.read('wifi_devices.conf')
rout_addr = (cf.get('Common','rout_addr'), 65381)
cl_level = eval(cf.get('Common','cl_level'))
fl_level = eval(cf.get('Common','fl_level'))
rm_log = eval(cf.get('Common','rm_log'))

class DoorSensorCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = get_mac_by_tick()
        self.device_type = "DoorSensor"
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



class DoorSensor(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(DoorSensor, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                         deviceCategory='doorsensor.main')
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
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log')
    if rm_log and os.path.isfile(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=cl_level, flevel=fl_level)
    cprint = cprint(__name__)
    doorSensorcmd = DoorSensorCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (doorSensorcmd.mac,))
    doorSensorcmd.cmdloop()