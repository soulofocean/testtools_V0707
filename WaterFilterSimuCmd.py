#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-7-3'
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


class WaterFilterCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180703"
        self.mac = get_mac_by_tick()
        self.device_type = "Waterfilter"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()
        self.onoff_kv = {"0": "off", "1": "on"}

    def help_clean(self):
        self.cprint.notice_p("clean the waterfilter:clean")

    def do_clean(self, arg):
        self.sim_obj.set_item('_status', 'clean')
        self.sim_obj.task_obj.add_task(
            'change WaterFilter to filter', self.sim_obj.set_item, 1, 100, '_status', 'standby')

    def help_rsf(self):
        self.cprint.notice_p("reset filter : rsf [id[1-2]] 0 for all")

    def do_rsf(self, arg):
        args = arg.split()
        if (len(args) != 1 or not args[0].isdigit() or int(args[0]) > 2):
            self.help_rsf()
        else:
            if (int(args[0]) == 0):
                self.sim_obj.reset_filter_time(1)
                self.sim_obj.reset_filter_time(2)
            else:
                self.sim_obj.reset_filter_time(int(args[0]))


class Waterfilter(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Waterfilter, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay, self_addr=self_addr,
                                          deviceCategory='water_filter.main',
                                          manufacture="tcl", deviceModel="TRO509-4")
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,mac=mac, deviceCategory='water_filter.main', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        self._filter_result = {
            "TDS": [
                500,
                100
            ]
        }
        self._status = 'standby'
        self._water_leakage = "off"
        self._water_shortage = "off"
        self._filter_time_total = [
            2000,
            2000,
        ]
        self._filter_time_remaining = [
            1000,
            1000,
        ]
        self._filter_lifetime = [
            15,
            23
        ]
        self._filter_status = "normal"
        self._water_leakage = "off"
        self._water_shortage = "off"

    def reset_filter_time(self, id):
        if int(id) in self._filter_time_total:
            self._filter_time_remaining[int(
                id)] = self._filter_time_total[int(id)]
            return True
        else:
            self.LOG.error('Unknow ID: %s' % (id))
            return False

    def get_event_report(self):
        report_msg = {
            "method": "report",
            "attribute": {
                "water_filter_result": self._filter_result,
                "status": self._status,
                "filter_time_total": self._filter_time_total,
                "filter_time_remaining": self._filter_time_remaining,
                "filter_lifetime": self._filter_lifetime,
                "filter_status": self._filter_status,
                "water_shortage": self._water_shortage,
                "water_leakage": self._water_leakage
            }
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"water_filter.main.all_properties":
                self.LOG.warn("获取所有属性".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    "attribute": {
                        "water_filter_result": self._filter_result,
                        "status": self._status,
                        "filter_time_total": self._filter_time_total,
                        "filter_time_remaining": self._filter_time_remaining,
                        "filter_lifetime": self._filter_lifetime,
                        "filter_status": self._filter_status,
                        "water_shortage": self._water_shortage,
                        "water_leakage": self._water_leakage
                    }
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':
            if msg['nodeid'] == u"water_filter.main.control":
                self.LOG.warn(
                    ("设置冲洗: %s" % (msg['params']["attribute"]["control"])).encode(coding))
                self.set_item('_status', msg['params']["attribute"]["control"])
                self.task_obj.add_task(
                    'change WaterFilter to filter', self.set_item, 1, 100, '_status', 'standby')
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"water_filter.main.reset_filter":
                self.LOG.warn(
                    ("复位滤芯: %s" % (msg['params']["attribute"]["reset_filter"])).encode(coding))
                filter_ids = msg['params']["attribute"]["reset_filter"]
                if 0 in filter_ids:
                    filter_ids = self._filter_time_total
                for filter_id in filter_ids:
                    self.reset_filter_time(filter_id)
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"wifi.main.alarm_confirm":
                return self.alarm_confirm_rsp(msg['req_id'], msg['params']["attribute"]["error_code"])

            else:
                self.LOG.warn('Unknow msg!')

        else:
            self.LOG.error('Msg wrong!')


if __name__ == '__main__':
    cf.read('wifi_devices.conf')
    rout_addr = (cf.get('Common', 'rout_addr'), 65381)
    cl_level = eval(cf.get('Common', 'cl_level'))
    fl_level = eval(cf.get('Common', 'fl_level'))
    rm_log = eval(cf.get('Common', 'rm_log'))
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe', 'log')
    if rm_log and os.path.isfile(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=cl_level, flevel=fl_level)
    cprint = cprint(__name__)
    airCmd = WaterFilterCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (airCmd.mac,))
    airCmd.cmdloop()
