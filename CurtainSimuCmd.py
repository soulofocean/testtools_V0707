#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-9'
"""
import json
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


class CurtainCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = get_mac_by_tick()
        self.device_type = "Curtain_Wifi"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()
        self.onoff_kv = {"0": "off", "1": "on", "2": "pause"}


class Curtain_Wifi(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Curtain_Wifi, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                           deviceCategory='curtain.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='air_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._switch = 'off'
        self._open_percentage = 0

    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "switch": self._switch,
                "open_percentage": self._open_percentage
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"curtain.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "switch": self._switch,
                        "open_percentage": self._open_percentage
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"curtain.main.switch":
                self.LOG.warn(
                    ("开/关/暂停窗帘: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_switch',
                              msg['params']["attribute"]["switch"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"curtain.main.open_percentage":
                self.LOG.warn(
                    ("指定开关幅度: %s" % (msg['params']["attribute"]["open_percentage"])).encode(coding))
                self.set_item('_open_percentage',
                              msg['params']["attribute"]["open_percentage"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
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
    curtainCmd = CurtainCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (curtainCmd.mac,))
    curtainCmd.cmdloop()