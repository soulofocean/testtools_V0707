#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-10'
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

class BulbCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = get_mac_by_tick()
        self.device_type = "Bulb_Wifi"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()



class Bulb_Wifi(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Bulb_Wifi, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                        deviceCategory='bulb.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._switch = 'off'
        self._level = 0x0
        self._transition_time = 0x0
        self._r = 0x0
        self._g = 0x0
        self._b = 0x0
        self._hue = 0
        self._saturation = 0
        self._temperature = 40


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "switch": self._switch,
                "level": self._level,
                "transition_time": self._transition_time,
                "r": self._r,
                "g": self._g,
                "b": self._b,
                "hue": self._hue,
                "saturation": self._saturation,
                "temperature": self._temperature
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"bulb.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "switch": self._switch,
                        "level": self._level,
                        "transition_time": self._transition_time,
                        "r": self._r,
                        "g": self._g,
                        "b": self._b,
                        "hue": self._hue,
                        "saturation": self._saturation,
                        "temperature": self._temperature
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"bulb.main.switch":
                self.LOG.warn(
                    ("设置开灯: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_switch', msg['params']["attribute"]["switch"])

            elif msg['nodeid'] == u"bulb.main.level":
                self.LOG.warn(
                    ("设置亮度: %s" % (str(msg['params']["attribute"]),)).encode(coding))
                self.set_item('_level', msg['params']["attribute"]["level"])
                self.set_item('_transition_time', msg['params']["attribute"]["transition_time"])
                need_confirm = msg['params']["attribute"]["need_confirm"]
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"bulb.main.rgb":
                self.LOG.warn(
                    ("设置颜色: %s" % (str(msg['params']["attribute"]),)).encode(coding))
                self.set_item('_r', msg['params']["attribute"]["r"])
                self.set_item('_g', msg['params']["attribute"]["g"])
                self.set_item('_b', msg['params']["attribute"]["b"])
                self.set_item('_transition_time', msg['params']["attribute"]["transition_time"])
                need_confirm = msg['params']["attribute"]["need_confirm"]
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"bulb.main.hue":
                self.LOG.warn(
                    ("设置色调: %s" % (msg['params']["attribute"])).encode(coding))
                self.set_item('_hue', msg['params']["attribute"]["hue"])
                self.set_item('_saturation', msg['params']["attribute"]["saturation"])
                self.set_item('_transition_time', msg['params']["attribute"]["transition_time"])
                need_confirm = msg['params']["attribute"]["need_confirm"]
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"bulb.main.temperature":
                self.LOG.warn(
                    ("设置色温: %s" % (msg['params']["attribute"]["temperature"])).encode(coding))
                self.set_item('_temperature', msg['params']["attribute"]["temperature"])
                self.set_item('_transition_time', msg['params']["attribute"]["transition_time"])
                need_confirm = msg['params']["attribute"]["need_confirm"]
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
    bulb_cmd = BulbCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (bulb_cmd.mac,))
    bulb_cmd.cmdloop()