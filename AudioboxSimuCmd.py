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


class AudioboxCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "Audiobox"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()


class Audiobox(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Audiobox, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                       deviceCategory='audiobox.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='air_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._play_mode = "cycle"

    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "play_mode": self._play_mode
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"audiobox.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "play_mode": self._play_mode
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"audiobox.main.play_ctl":
                self.LOG.warn(
                    ("播放功能: %s" % (msg['params']["attribute"]["play_ctl"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"audiobox.main.voice":
                self.LOG.warn(
                    ("设置音量: %s" % (msg['params']["attribute"]["voice"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"audiobox.main.song":
                self.LOG.warn(
                    ("歌曲选择: %s" % (msg['params']["attribute"]["song"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"audiobox.main.play_mode":
                self.LOG.warn(
                    ("设置播放模式: %s" % (msg['params']["attribute"]["play_mode"])).encode(coding))
                self.set_item('_play_mode',
                              msg['params']["attribute"]["play_mode"])
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
    audioboxCmd = AudioboxCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (audioboxCmd.mac,))
    audioboxCmd.cmdloop()