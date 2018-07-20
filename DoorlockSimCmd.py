#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-11'
"""
import json
from basic.BasicCommon import *
from basic.BasicSimuCmd import BasicCmd, BaseWifiSim

# region const variates
rout_addr = ('192.168.10.1', 65381)


class DoorlockCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Doorlock_wifi"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()


class Doorlock_wifi(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Doorlock_wifi, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                            deviceCategory='doorlock.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='air_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._switch = 'off'
        self._switch_open_cnt = 0
        self._switch_close_cnt = 0
        self._user_identify = 2147483648
        self._open_type = 0
        self._battery_percentage = 100

    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "switch": self._switch,
                "switch_open_cnt": self._switch_open_cnt,
                "switch_close_cnt": self._switch_close_cnt,
                "user_identify": self._user_identify,
                "open_type": self._open_type,
                "battery_percentage": self._battery_percentage
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"doorlock.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "switch": self._switch,
                        "switch_open_cnt": self._switch_open_cnt,
                        "switch_close_cnt": self._switch_close_cnt,
                        "user_identify": self._user_identify,
                        "open_type": self._open_type,
                        "battery_percentage": self._battery_percentage
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"doorlock.main.switch":
                self.LOG.warn(
                    ("开关门: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                sw = msg['params']["attribute"]["switch"]
                if(sw == 'off'):
                    self.set_item('_switch_close_cnt', self.get_item('_switch_close_cnt') + 1)
                else:
                    self.set_item('switch_open_cnt', self.get_item('switch_open_cnt') + 1)
                    pwd = msg['params']["attribute"]["pwd"]
                    pwd ^= 0xA5
                self.set_item('_switch',sw)
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')


if __name__ == '__main__':
    LOG = MyLogger(os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log'), clevel=logging.DEBUG,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    doorlockCmd = DoorlockCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (doorlockCmd.mac,))
    doorlockCmd.cmdloop()