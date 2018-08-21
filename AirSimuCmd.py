#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-6-28'
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


class AirCmd(BasicCmd):
    def __init__(self, logger, cprint):
        self.air_version = "20180628"
        self.mac = get_mac_by_tick()
        self.device_type = "Air"
        BasicCmd.__init__(self, logger=logger, cprint=cprint, version=self.air_version, d_type=self.device_type)
        self.sim_obj = eval(self.device_type)(logger, mac=self.mac, addr=rout_addr)
        self.do_start()
        self.onoff_kv = {"0": "off", "1": "on"}
        self.mode_kv = {"0": "auto", "1": "cold", "2": "heat", "3": "dehumidity", "4": "wind"}
        self.speed_kv = {"0": "low", "1": "overlow", "2": "normal", "3": "overnormal", "4": "high", "5": "auto"}

    def help_switch(self):
        self.cprint.notice_p("switch %s:switch %s" % (self.device_type, self.onoff_kv))

    def do_switch(self, arg):
        args = arg.split()
        if (len(args) != 1 or args[0] not in self.onoff_kv):
            self.help_switch()
        else:
            self.sim_obj.set_item("_switchStatus", self.onoff_kv[args[0]])

    def help_mode(self):
        self.cprint.notice_p("set %s mode:mode %s" % (self.device_type, self.mode_kv))

    def do_mode(self, arg):
        args = arg.split()
        if (len(args) != 1 or args[0] not in self.mode_kv):
            self.help_mode()
        else:
            self.sim_obj.set_item("_mode", self.mode_kv[args[0]])

    def help_speed(self):
        self.cprint.notice_p('set %s speed:speed %s' % (self.device_type, self.speed_kv))

    def do_speed(self, arg):
        args = arg.split()
        if (len(args) != 1 or args[0] not in self.speed_kv):
            self.help_speed()
        else:
            self.sim_obj.set_item("_speed", self.speed_kv[args[0]])

    def help_wind_ud(self):
        self.cprint.notice_p("set %s wind_up_down:wind_ud %s" % (self.device_type, self.onoff_kv))

    def do_wind_ud(self, arg):
        args = arg.split()
        if (len(args) != 1 or args[0] not in self.onoff_kv):
            self.help_wind_ud()
        else:
            self.sim_obj.set_item("_wind_up_down", self.onoff_kv[args[0]])

    def help_wind_lr(self):
        self.cprint.notice_p("set %s wind_left_right:wind_lr %s" % (self.device_type, self.onoff_kv))

    def do_wind_lr(self, arg):
        args = arg.split()
        if (len(args) != 1 or args[0] not in self.onoff_kv):
            self.help_wind_ud()
        else:
            self.sim_obj.set_item("_wind_left_right", self.onoff_kv[args[0]])

    def help_tp(self):
        self.cprint.notice_p("set %s temperature:tp [160,300]" % (self.device_type,))

    def do_tp(self, arg):
        args = arg.split()
        if (len(args) != 1 or not args[0].isdigit() or int(args[0]) < 160 or int(args[0]) > 300):
            self.help_tp()
        else:
            self.sim_obj.set_item("_temperature", int(args[0]))


class Air(BaseWifiSim):
    def __init__(self, logger, mac='123456', time_delay=500, self_addr=None, addr=('192.168.10.1', 65381)):
        super(Air, self).__init__(logger, addr=addr, mac=mac, time_delay=time_delay
                                  , self_addr=self_addr, deviceCategory='airconditioner.new',
                                  manufacture="tcl", deviceModel="KFRd-51LW/RC11BpA")
        # self.LOG = logger
        # self.sdk_obj = Wifi(logger=logger, time_delay=time_delay
        # , mac=mac, deviceCategory='airconditioner.new', self_addr=self_addr)
        # self.sdk_obj.sim_obj = self

        # state data:
        # self._switchStatus = 'off'
        # self._temperature = 16
        # self._mode = "cold"
        # self._speed = "low"
        # self._wind_up_down = 'off'
        # self._wind_left_right = 'off'
        # add by zx 20180524
        self.attr_dict = {
            "switchStatus": 'off',
            "temperature": 160,
            "mode": 'cold',
            "speed": 'low',
            "wind_up_down": 'off',
            "wind_left_right": 'off',
            "env_temperature": 205,
            "powersave_mode": 'off',
            "sleep_mode": 'off',
            "comfort_mode": 'off',
            "enforce_mode": 'off',
            "clean_mode": 'off',
            "health_mode": 'off',
            "quiet_mode": 'off',
            "natural_mode": 'off',
            "auxiliary_heating_mode": 'off',
            "indicator_light": 'off',
            "scene_light": 'off',
            "timer_switch": 'off',
            "time_value": 1
        }
        self.initAttrAndDict(initDict=False)

    def get_event_report(self):
        self.LOG.warn("get_event_report".encode(coding))
        report_msg = {
            "method": "report",
            # "attribute": {
            # "switchStatus": self._switchStatus,
            # "temperature": self._temperature,
            # "mode": self._mode,
            # "speed": self._speed,
            # "wind_up_down": self._wind_up_down,
            # "wind_left_right": self._wind_left_right
            # }
            "attribute": self.initAttrAndDict(initAttr=False)
        }
        return json.dumps(report_msg)

    def protocol_handler(self, msg):
        coding = sys.getfilesystemencoding()
        if msg['method'] == 'dm_get':
            if msg['nodeid'] == u"airconditioner.new.all_properties":
                self.LOG.warn("获取所有属性new".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    # "attribute": {
                    # "switchStatus": self._switchStatus,
                    # "temperature": self._temperature,
                    # "mode": self._mode,
                    # "speed": self._speed,
                    # "wind_up_down": self._wind_up_down,
                    # "wind_left_right": self._wind_left_right
                    # }
                    "attribute": self.initAttrAndDict(initAttr=False)
                }
                return json.dumps(rsp_msg)
            if msg['nodeid'] == u"airconditioner.main.all_properties":
                self.LOG.warn("获取所有属性main".encode(coding))
                rsp_msg = {
                    "method": "dm_get",
                    "req_id": msg['req_id'],
                    "msg": "success",
                    "code": 0,
                    # "attribute": {
                    # "switchStatus": self._switchStatus,
                    # "temperature": self._temperature,
                    # "mode": self._mode,
                    # "speed": self._speed,
                    # "wind_up_down": self._wind_up_down,
                    # "wind_left_right": self._wind_left_right
                    # }
                    "attribute": self.initAttrAndDict(initAttr=False)
                }
                return json.dumps(rsp_msg)
            else:
                self.LOG.warn('Unknow msg!')

        elif msg['method'] == 'dm_set':

            if msg['nodeid'] == u"condition.main.switch":
                self.LOG.warn(
                    ("开关机: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_switchStatus',
                              msg['params']["attribute"]["switch"])
                return self.dm_set_rsp(msg['req_id'])
            elif msg['nodeid'] == u"airconditioner.main.switch":
                self.LOG.warn(
                    ("开关机: %s" % (msg['params']["attribute"]["switch"])).encode(coding))
                self.set_item('_switchStatus',
                              msg['params']["attribute"]["switch"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.mode":
                self.LOG.warn(
                    ("设置模式: %s" % (msg['params']["attribute"]["mode"])).encode(coding))
                self.set_item('_mode', msg['params']["attribute"]["mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.temperature":
                self.LOG.warn(
                    ("设置温度: %s" % (msg['params']["attribute"]["temperature"])).encode(coding))
                self.set_item('_temperature',
                              msg['params']["attribute"]["temperature"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.speed":
                self.LOG.warn(
                    ("设置风速: %s" % (msg['params']["attribute"]["speed"])).encode(coding))
                self.set_item('_speed', msg['params']["attribute"]["speed"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.wind_up_down":
                self.LOG.warn(
                    ("设置上下摆风: %s" % (msg['params']["attribute"]["wind_up_down"])).encode(coding))
                self.set_item('_wind_up_down',
                              msg['params']["attribute"]["wind_up_down"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.wind_left_right":
                self.LOG.warn(
                    ("设置左右摆风: %s" % (msg['params']["attribute"]["wind_left_right"])).encode(coding))
                self.set_item('_wind_left_right',
                              msg['params']["attribute"]["wind_left_right"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.powersave_mode":
                self.LOG.warn(
                    ("省电模式: %s" % (msg['params']["attribute"]["powersave_mode"])).encode(coding))
                self.set_item('_powersave_mode',
                              msg['params']["attribute"]["powersave_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.sleep_mode":
                self.LOG.warn(
                    ("睡眠模式: %s" % (msg['params']["attribute"]["sleep_mode"])).encode(coding))
                self.set_item('_sleep_mode',
                              msg['params']["attribute"]["sleep_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.comfort_mode":
                self.LOG.warn(
                    ("舒适模式: %s" % (msg['params']["attribute"]["comfort_mode"])).encode(coding))
                self.set_item('_comfort_mode',
                              msg['params']["attribute"]["comfort_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.enforce_mode":
                self.LOG.warn(
                    ("增强模式: %s" % (msg['params']["attribute"]["enforce_mode"])).encode(coding))
                self.set_item('_enforce_mode',
                              msg['params']["attribute"]["enforce_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.clean_mode":
                self.LOG.warn(
                    ("自清洁模式: %s" % (msg['params']["attribute"]["clean_mode"])).encode(coding))
                self.set_item('_clean_mode',
                              msg['params']["attribute"]["clean_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.health_mode":
                self.LOG.warn(
                    ("健康模式: %s" % (msg['params']["attribute"]["health_mode"])).encode(coding))
                self.set_item('_health_mode',
                              msg['params']["attribute"]["health_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.quiet_mode":
                self.LOG.warn(
                    ("安静模式: %s" % (msg['params']["attribute"]["quiet_mode"])).encode(coding))
                self.set_item('_quiet_mode',
                              msg['params']["attribute"]["quiet_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.natural_mode":
                self.LOG.warn(
                    ("自然风开关: %s" % (msg['params']["attribute"]["natural_mode"])).encode(coding))
                self.set_item('_natural_mode',
                              msg['params']["attribute"]["natural_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.auxiliary_heating_mode":
                self.LOG.warn(
                    ("辅热开关: %s" % (msg['params']["attribute"]["auxiliary_heating_mode"])).encode(coding))
                self.set_item('_auxiliary_heating_mode',
                              msg['params']["attribute"]["auxiliary_heating_mode"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.indicator_light":
                self.LOG.warn(
                    ("指示灯开关: %s" % (msg['params']["attribute"]["indicator_light"])).encode(coding))
                self.set_item('_indicator_light',
                              msg['params']["attribute"]["indicator_light"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.scene_light":
                self.LOG.warn(
                    ("情景灯开关: %s" % (msg['params']["attribute"]["scene_light"])).encode(coding))
                self.set_item('_scene_light',
                              msg['params']["attribute"]["scene_light"])
                return self.dm_set_rsp(msg['req_id'])

            elif msg['nodeid'] == u"airconditioner.main.time":
                self.LOG.warn(
                    ("设置倒计时: %s" % (msg['params']["attribute"])).encode(coding))
                self.set_item('_timer_switch',
                              msg['params']["attribute"]["timer_switch"])
                self.set_item('_time_value',
                              msg['params']["attribute"]["time_value"])
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
    airCmd = AirCmd(logger=LOG, cprint=cprint)
    cprint.yinfo_p("start simu mac [%s]" % (airCmd.mac,))
    airCmd.cmdloop()
