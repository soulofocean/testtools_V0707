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

# region const variates
rout_addr = ('192.168.10.1', 65381)

class SwitchCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Switch_Wifi"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()



class Switch_Wifi(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Switch_Wifi, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                          deviceCategory='switch.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._switch = 'off'
        self._chan_num = 0x1
        self._uuid_chan0 = ['',]
        self._is_config_device = '1'
        self._chan0_name = 'chan0'
        self._chan0_avatar = 'chan0.png'


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "switch": self._switch,
                "chan_num": self._chan_num,
                "uuid_chan0": self._uuid_chan0,
                "is_config_device": self._is_config_device,
                "chan0_name": self._chan0_name,
                "chan0_avatar": self._chan0_avatar
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"switch.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "switch": self._switch,
                        "chan_num": self._chan_num,
                        "uuid_chan0": self._uuid_chan0,
                        "is_config_device": self._is_config_device,
                        "chan0_name": self._chan0_name,
                        "chan0_avatar": self._chan0_avatar
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"switch.main.switch":
                self.LOG.warn(
                    ("设置开关: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_switch', msg['params']["attribute"]["switch"])

            elif msg['nodeid'] == u"switch.main.bind":
                self.LOG.warn(
                    ("绑定开关灯: %s" % (str(msg['params']["attribute"]["switch_chan0"]),)).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"switch.main.config":
                self.LOG.warn(
                    ("绑定开关设备: %s" % (msg['params']["attribute"]["chan"])).encode(coding))
                chanInfo = msg['params']["attribute"]["chan"]
                chan_num = re.findall("\d+$", chanInfo)[0]
                chan_key = "_uuid_chan%s" % (chan_num,)
                self.set_item(chan_key, msg['params']["attribute"][chan_key])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"switch.main.is_config_device":
                self.LOG.warn(
                    ("配置子设备支持: %s" % (msg['params']["attribute"]["is_config_device"])).encode(coding))
                self.set_item('_is_config_device', msg['params']["attribute"]["is_config_device"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"switch.main.chan_config":
                self.LOG.warn(
                    ("设置开关名图: %s" % (msg['params']["attribute"])).encode(coding))
                for k,v in msg['params']["attribute"]:
                    self.set_item("_%s" % (k,), v)
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
    switch_cmd = SwitchCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (switch_cmd.mac,))
    switch_cmd.cmdloop()