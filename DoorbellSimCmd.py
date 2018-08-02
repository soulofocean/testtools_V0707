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

class DoorbellCmd(BasicCmd):
    def __init__(self, rstp_dict, logger, cprint):
        self.air_version = "20180706"
        self.mac = get_mac_by_tick()
        self.device_type = "Doorbell"
        BasicCmd.__init__(self,logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, rstp_dict, mac=self.mac, addr=rout_addr)
        self.do_start()


class Doorbell(BaseWifiSim):
    def __init__(self, logger, rstp_dict, name='admin', pwd='admin',
                 mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Doorbell, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                       deviceCategory='doorbell.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._voice = 'release'
        self._audio = 'off'
        self._record_method = 'motion_detect'
        self._md_sensitivity = 'general'
        self._sdcard_msg = {
            "status" : "ok",
            "format_result" : "success",
            "total" : 1000,
            "unused" : 100
        }
        self.rstp_dict = rstp_dict
        self.name = name
        self.pwd = pwd

    def stream_rsp(self, req, channel):
        rsp_msg = {
            "method": "dm_set",
            "req_id": req,
            "msg": "success",
            "code": 0,
            "attribute":{
                "url": self.rstp_dict[channel]
            }
        }
        return json.dumps(rsp_msg)

    def record_msg_rsp(self,req,timestamp,number,direction):
        timeArray = time.localtime(timestamp)
        #time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
        dataStr = time.strftime("%Y-%m-%d", timeArray)
        file1 = ("%02d-%02d/%sM.mp4" % (timeArray.tm_hour,(timeArray.tm_hour+1)%24
                                        ,time.strftime("%H%M%S", timeArray)))
        file2 = ("%02d-%02d/%sD.mp4" % (timeArray.tm_hour, (timeArray.tm_hour + 1) % 24
                                        , time.strftime("%H%M%S", timeArray)))
        firstFile = file1
        lastFile = file2
        rsp_msg = {
            "method": "dm_get",
            "req_id": req,
            "msg": "success",
            "code": 0,
            "attribute": {
                "total": 2,
                "more": 0,
                "first": firstFile,
                "last": lastFile,
                "list":[
                    {
                        "data": dataStr,
                        "file": file1
                    },
                    {
                        "data": dataStr,
                        "file": file2
                    }
                ]
            }
        }
        return json.dumps(rsp_msg)

    def auth_msg_rsp(self,req):
        rsp_msg = {
            "method": "dm_set",
            "req_id": req,
            "msg": "success",
            "code": 0,
            "attribute": {
                "username" : self.name,
                "password" : self.pwd
            }
        }
        return json.dumps(rsp_msg)

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

            elif msg['nodeid'] == u"ipc.main.record_msg":
                self.LOG.warn(
                    ("获取文件: %s" % (msg['params']["attribute"])).encode(coding))
                timestamp = msg['params']["attribute"]["time"]
                number = msg['params']["attribute"]["number"]
                direction = msg['params']["attribute"]["direction"]
                return self.record_msg_rsp(msg['req_id'],timestamp, number, direction)

            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':

            if msg['nodeid'] == u"doorbell.main.stream":
                self.LOG.warn(
                    ("获取流通道: %s" % (msg['params']["attribute"]["channel"])).encode(coding))
                return self.stream_rsp(msg['req_id'],msg['params']["attribute"]["channel"])

            elif msg['nodeid'] == u"doorbell.main.record_method":
                self.LOG.warn(
                    ("移动侦测: %s" % (msg['params']["attribute"]["type"])).encode(coding))
                self.set_item('_record_method', msg['params']["attribute"]["type"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.md_sensitivity":
                self.LOG.warn(
                    ("移动侦测: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_md_sensitivity', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.sd_format":
                self.LOG.warn(
                    ("sd格式化: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.set_time":
                self.LOG.warn(
                    ("设置时间: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.auth_msg":
                self.LOG.warn(
                    ("设置时间: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                return self.auth_msg_rsp(msg['req_id'])

            elif msg['nodeid'] == u"doorbell.main.audio":
                self.LOG.warn(
                    ("语音上行开关: %s" % (msg['params']["attribute"]["audio"])).encode(coding))
                self.set_item('_audio', msg['params']["attribute"]["audio"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')

def get_rstp_addr_dict():
    rstp_dict = {}
    rstp_dict["main"] = cf.get('DoorBell','main')
    rstp_dict["sub"] = cf.get('DoorBell', 'sub')
    rstp_dict["file"] = cf.get('DoorBell', 'file')
    return rstp_dict

if __name__ == '__main__':
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log')
    if rm_log and os.path.isfile(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=cl_level, flevel=fl_level)
    cprint = cprint(__name__)
    doorbellCmd = DoorbellCmd(get_rstp_addr_dict(), logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (doorbellCmd.mac,))
    doorbellCmd.cmdloop()