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

class AirQDCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "AirQD"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()



class AirQD(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(AirQD, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                    deviceCategory='airqualitydetector.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._humidity = 3000
        self._temperature = 188
        self._air_pressure = 1013
        self._pm25 = 5000
        self._pm10 = 5000
        self._formaldehyde = 10000
        self._tvoc = 500
        self._co2 = 10000
        self._co = 500


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "humidity": self._humidity,
                "temperature": self._temperature,
                "air_pressure": self._air_pressure,
                "pm25": self._pm25,
                "pm10": self._pm10,
                "formaldehyde": self._formaldehyde,
                "tvoc": self._tvoc,
                "co2": self._co2,
                "co": self._co
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"airqualitydetector.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "humidity": self._humidity,
                        "temperature": self._temperature,
                        "air_pressure": self._air_pressure,
                        "pm25": self._pm25,
                        "pm10": self._pm10,
                        "formaldehyde": self._formaldehyde,
                        "tvoc": self._tvoc,
                        "co2": self._co2,
                        "co": self._co
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':

            if msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')


if __name__ == '__main__':
    LOG = MyLogger(os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log'), clevel=logging.DEBUG,
                   rlevel=logging.WARN)
    cprint = cprint(__name__)
    airQDcmd = AirQDCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (airQDcmd.mac,))
    airQDcmd.cmdloop()