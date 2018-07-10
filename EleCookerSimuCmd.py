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

class EleCookerCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180706"
        self.mac = str(hex(int(time.time())))[-8:]
        self.device_type = "EleCooker"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()


class EleCooker(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(EleCooker, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                        deviceCategory='electriccooker.main')
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._cooking_mode = 0
        self._cooking_taste = 0
        self._cooking_time = 0
        self._order_mode = 0
        self._order_taste = 0
        self._order_time = 0
        self._heating_mode = 'keep'
        self._heating_capacity = 'LVn'
        self._heating_temp = 40
        self._self_cleaning = 'off'
        self._steam_exhaust = ''
        self._remain_reheating_time = 0
        self._remain_selfcleaning_time = 0
        self._remain_cooking_time = 0
        self._heating_time = 0


    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "cooking_mode": self._cooking_mode,
                "cooking_taste": self._cooking_taste,
                "cooking_time": self._cooking_time,
                "order_mode": self._order_mode,
                "order_taste": self._order_taste,
                "order_time": self._order_time,
                "heating_mode": self._heating_mode,
                "heating_capacity": self._heating_capacity,
                "heating_temp": self._heating_temp,
                "self_cleaning": self._self_cleaning,
                "steam_exhaust": self._steam_exhaust,
                "remain_reheating_time": self._remain_reheating_time,
                "remain_selfcleaning_time": self._remain_selfcleaning_time,
                "remain_cooking_time": self._remain_cooking_time,
                "heating_time": self._heating_time
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"electriccooker.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "cooking_mode": self._cooking_mode,
                        "cooking_taste": self._cooking_taste,
                        "cooking_time": self._cooking_time,
                        "order_mode": self._order_mode,
                        "order_taste": self._order_taste,
                        "order_time": self._order_time,
                        "heating_mode": self._heating_mode,
                        "heating_capacity": self._heating_capacity,
                        "heating_temp": self._heating_temp,
                        "self_cleaning": self._self_cleaning,
                        "steam_exhaust": self._steam_exhaust,
                        "remain_reheating_time": self._remain_reheating_time,
                        "remain_selfcleaning_time": self._remain_selfcleaning_time,
                        "remain_cooking_time": self._remain_cooking_time,
                        "heating_time": self._heating_time
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"electriccooker.main.cooking":
                self.LOG.warn(
                    ("设置煮饭: %s" % (msg['params']["attribute"]["cooking_mode"])).encode(coding))
                self.set_item('_cooking_mode', msg['params']["attribute"]["cooking_mode"])
                self.set_item('_cooking_taste', msg['params']["attribute"]["cooking_taste"])
                self.set_item('_cooking_time', msg['params']["attribute"]["cooking_time"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"electriccooker.main.order":
                self.LOG.warn(
                    ("设置预约: %s" % (msg['params']["attribute"]["order_mode"])).encode(coding))
                self.set_item('_order_mode', msg['params']["attribute"]["order_mode"])
                self.set_item('_order_taste', msg['params']["attribute"]["order_taste"])
                self.set_item('_order_time', msg['params']["attribute"]["order_time"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"electriccooker.main.heating":
                self.LOG.warn(
                    ("设置加热: %s" % (msg['params']["attribute"]["heating_mode"])).encode(coding))
                self.set_item('_heating_mode', msg['params']["attribute"]["heating_mode"])
                self.set_item('_heating_capacity', msg['params']["attribute"]["heating_capacity"])
                self.set_item('_heating_temp', msg['params']["attribute"]["heating_temp"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"electriccooker.main.self_cleaning":
                self.LOG.warn(
                    ("设置清洗: %s" % (msg['params']["attribute"]["self_cleaning"])).encode(coding))
                self.set_item('_self_cleaning', msg['params']["attribute"]["self_cleaning"])
                self.set_item('_remain_selfcleaning_time', 10)
                self.task_obj.add_task(
                    'change _remain_selfcleaning_time', self.set_item, 1, 100, '_remain_selfcleaning_time', 0)
                self.task_obj.add_task(
                    'change _self_cleaning', self.set_item, 1, 100, '_self_cleaning', 'off')
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"electriccooker.main.cancel":
                self.LOG.warn(
                    ("设置取消: %s" % (msg['params']["attribute"]["cancel"])).encode(coding))
                self.set_item('_remain_reheating_time', 0)
                self.set_item('_remain_selfcleaning_time', 0)
                self.set_item('_remain_cooking_time', 0)

                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"electriccooker.main.start_status":
                self.LOG.warn(
                    ("启动设备: %s" % (msg['params']["attribute"]["start_status"])).encode(coding))
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
    eleCookerCmd = EleCookerCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (eleCookerCmd.mac,))
    eleCookerCmd.cmdloop()