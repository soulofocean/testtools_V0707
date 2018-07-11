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

class DoorbellCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Doorbell"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()


class Doorbell(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Doorbell, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                       deviceCategory='doorbell.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._voice = 'release'
        self._audio = 'off'
        self._record_method = 'motion_detect'
        self._sdcard_msg = {
            "status" : "ok",
            "total" : 1000,
            "unused" : 100
        }


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "voice": self._voice,
                "audio": self._audio,
                "record_method": self._record_method,
                "sdcard_msg": self._sdcard_msg
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"doorbell.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "voice": self._voice,
                        "audio": self._audio,
                        "record_method": self._record_method,
                        "sdcard_msg": self._sdcard_msg
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"doorbell.main.accept":
                self.LOG.warn(
                    ("接听: %s" % (msg['params']["attribute"]["callid"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.open":
                self.LOG.warn(
                    ("开门: %s" % (msg['params']["attribute"]["callid"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.close":
                self.LOG.warn(
                    ("异步挂断: %s" % (msg['params']["attribute"]["callid"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.async_call":
                self.LOG.warn(
                    ("异步呼叫: %s" % (msg['params']["attribute"]["callid"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.audio":
                self.LOG.warn(
                    ("语音上行开关: %s" % (msg['params']["attribute"]["audio"])).encode(coding))
                self.set_item('_audio', msg['params']["attribute"]["audio"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.record_method":
                self.LOG.warn(
                    ("移动侦测: %s" % (msg['params']["attribute"]["type"])).encode(coding))
                self.set_item('_record_method', msg['params']["attribute"]["type"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.sd_format":
                self.LOG.warn(
                    ("sd格式化: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')


if __name__ == '__main__':
    LOG = MyLogger(os.path.abspath(sys.argv[0]).replace('py', 'log'), clevel=logging.DEBUG,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    doorbellCmd = DoorbellCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (doorbellCmd.mac,))
    doorbellCmd.cmdloop()