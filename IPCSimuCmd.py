#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-6'
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

class IPCCmd(BasicCmd):
    def __init__(self,rstp, logger, cprint):
        self.air_version = "20180706"
        self.mac = get_mac_by_tick()
        self.device_type = "IPC"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger,rstp, mac=self.mac, addr=rout_addr)
        self.do_start()
        self.onoff_kv = {"0": "off", "1": "on"}


class IPC(BaseWifiSim):
    def __init__(self, logger, rstp_dict, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(IPC, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                  deviceCategory='ipc.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._pict_quality = 'general'
        self._resolution = "general"
        self._audio = 'off'
        self._flip = 'off'
        self._distortion_correction = 'off'
        self._ir_switch = 'off'
        self._osd = 'OSD_example'
        self._mic = 'off'
        self._encrypt_photo = 'off'
        self._pwd = 'your_pwd'
        self._record_method = 'motion_detect'
        self._md_sensitivity = 'general'
        self._cry = 'off'
        self._time_zone = 'utc+8'
        self._sdcard_msg = {
            "status" : "ok",
            "formate_result" : "success",
            "total" : 1000,
            "unused" : 100
        }
        self._voice = 'release'
        self.rstp_dict = rstp_dict


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "pict_quality": self._pict_quality,
                "resolution": self._resolution,
                "audio": self._audio,
                "flip": self._flip,
                "distortion_correction": self._distortion_correction,
                "ir_switch": self._ir_switch,
                "osd": self._osd,
                "mic": self._mic,
                "encrypt_photo": self._encrypt_photo,
                "pwd": self._pwd,
                "record_method": self._record_method,
                "md_sensitivity": self._md_sensitivity,
                "cry": self._cry,
                "time_zone": self._time_zone,
                "sdcard_msg": self._sdcard_msg,
                "voice": self._voice
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"ipc.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "pict_quality": self._pict_quality,
                        "resolution": self._resolution,
                        "audio": self._audio,
                        "flip": self._flip,
                        "distortion_correction": self._distortion_correction,
                        "ir_switch": self._ir_switch,
                        "osd": self._osd,
                        "mic": self._mic,
                        "encrypt_photo": self._encrypt_photo,
                        "pwd": self._pwd,
                        "record_method": self._record_method,
                        "md_sensitivity": self._md_sensitivity,
                        "cry": self._cry,
                        "time_zone": self._time_zone,
                        "sdcard_msg": self._sdcard_msg,
                        "voice": self._voice
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
            if msg['nodeid'] == u"ipc.main.pict_quality":
                self.LOG.warn(
                    ("设置画质: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_pict_quality', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.resolution":
                self.LOG.warn(
                    ("清晰控制: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_resolution', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.audio":
                self.LOG.warn(
                    ("语音ipc->app开关: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_audio', msg['params']["attribute"]["switch"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.flip":
                self.LOG.warn(
                    ("图像翻转: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_flip', msg['params']["attribute"]["switch"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.distortion_correction":
                self.LOG.warn(
                    ("畸变校正: %s" % (msg['params']["attribute"]["distortion_correction"])).encode(coding))
                self.set_item('_distortion_correction', msg['params']["attribute"]["distortion_correction"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.cloud_platform":
                self.LOG.warn(
                    ("云台旋转: %s" % (msg['params']["attribute"]["direction"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.ir_switch":
                self.LOG.warn(
                    ("红外夜视: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_ir_switch', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.osd":
                self.LOG.warn(
                    ("OSD: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_osd', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.mic":
                self.LOG.warn(
                    ("麦克风: %s" % (msg['params']["attribute"]["mic"])).encode(coding))
                self.set_item('_mic', msg['params']["attribute"]["mic"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.encrypt_photo":
                self.LOG.warn(
                    ("图片加密: %s" % (msg['params']["attribute"]["encrypt_photo"])).encode(coding))
                self.set_item('_encrypt_photo', msg['params']["attribute"]["encrypt_photo"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.pwd":
                self.LOG.warn(
                    ("密码设置: %s" % (msg['params']["attribute"]["pwd"])).encode(coding))
                self.set_item('_pwd', msg['params']["attribute"]["pwd"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.record_method":
                self.LOG.warn(
                    ("移动侦测: %s" % (msg['params']["attribute"]["type"])).encode(coding))
                self.set_item('_record_method', msg['params']["attribute"]["type"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.md_sensitivity":
                self.LOG.warn(
                    ("敏感度: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_md_sensitivity', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.cry":
                self.LOG.warn(
                    ("哭声侦测: %s" % (msg['params']["attribute"]["cry"])).encode(coding))
                self.set_item('_cry', msg['params']["attribute"]["cry"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.time_zone":
                self.LOG.warn(
                    ("时区设置: %s" % (msg['params']["attribute"]["time_zone"])).encode(coding))
                self.set_item('_time_zone', msg['params']["attribute"]["time_zone"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.sd_format":
                self.LOG.warn(
                    ("sd格式化: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                self.set_item('_sd_format', msg['params']["attribute"]["value"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.set_time":
                self.LOG.warn(
                    ("设置时间: %s" % (msg['params']["attribute"]["value"])).encode(coding))
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"ipc.main.stream":
                self.LOG.warn(
                    ("获取流通道: %s" % (msg['params']["attribute"]["channel"])).encode(coding))
                return self.stream_rsp(msg['req_id'],msg['params']["attribute"]["channel"])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')

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
            "method": "dm_set",
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

def get_rstp_addr_dict():
    rstp_dict = {}
    rstp_dict["main"] = cf.get('IPC','main')
    rstp_dict["sub"] = cf.get('IPC', 'sub')
    rstp_dict["file"] = cf.get('IPC', 'file')
    return rstp_dict

if __name__ == '__main__':
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log')
    if rm_log and os.path.isfile(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=cl_level, flevel=fl_level)
    cprint = cprint(__name__)
    ipcCmd = IPCCmd(get_rstp_addr_dict(), logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (ipcCmd.mac,))
    ipcCmd.cmdloop()