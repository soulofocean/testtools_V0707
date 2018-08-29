#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'ZengXu'
__mtime__ = '2018-6-29'
"""
import copy
from abc import ABCMeta
from BasicProtocol import *
from cmd import Cmd
from BasicCommon import *

if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')
coding = sys.getfilesystemencoding()


class BasicCmd(Cmd):
    def __init__(self, logger, cprint, version="20180628", d_type="Air"):
        Cmd.__init__(self)
        self.log_kv = [("0", "logging.CRITICAL"), ("1", "logging.ERROR"),
                       ("2", "logging.WARNING"), ("3", "logging.INFO"), ("4", "logging.DEBUG")]
        self.Log = logger
        self.cprint = cprint
        self.sim_obj = None
        # self.sim_obj = eval(d_type)(logger,mac=mac,addr=addr)
        self.prompt = "%s>>" % (d_type,)
        self.intro = "Welcome from %sCmd (Version:%s)!" % (d_type, version,)
        # self.do_log("3")
        # self.do_start()

    def emptyline(self):
        pass

    def help_set(self):
        self.cprint.notice_p("set state: set [key] [value]")

    def do_set(self, arg, opts=None):
        args = arg.split()
        self.sim_obj.set_item(args[0], args[1])

    def help_start(self):
        self.cprint.common_p("start simulator runforever")

    def help_exit(self):
        self.cprint.common_p("exit console")

    def do_start(self, arg=None):
        if self.sim_obj:
            self.sim_obj.run_forever()

    def do_exit(self, arg=None):
        self.cprint.common_p("Exit simulator, good bye!")
        sys.exit(0)

    def help_log(self):
        self.cprint.notice_p(
            "change logger level: log %s" % (self.log_kv,))

    def do_log(self, arg):
        args = arg.split()
        if (len(args) != 1 or not args[0].isdigit() or int(args[0]) > (len(self.log_kv) - 1)):
            self.cprint.warn_p("unknow log level: %s!" % (arg))
            self.help_log()
        else:
            self.Log.set_level(eval(self.log_kv[int(args[0])][1]))

    def help_show(self):
        self.cprint.notice_p("show simulator state")

    def do_show(self, arg=None):
        if not self.sim_obj == None:
            self.sim_obj.status_show()
        else:
            self.cprint.warn_p("Simulator is not started ...")

    def help_alarm(self):
        self.cprint.notice_p("send alarm:")
        self.cprint.notice_p("alarm error_code error_status error_level error_msg")

    def do_alarm(self, arg, opts=None):
        args = arg.split()
        if len(args) >= 2:
            if len(args) == 3:
                args.append('Test alarm')
            else:
                args.append(1)
                args.append('Test alarm')
            self.sim_obj.add_alarm(error_code=args[0], error_status=args[1], error_level=int(
                args[2]), error_msg=args[3])
        else:
            self.help_alarm()


alarm_lock = threading.Lock()


class BaseWifiSim():
    __metaclass__ = ABCMeta
    status_lock = threading.Lock()

    def __init__(self, logger, addr=('192.168.10.1', 65381), mac='123456', time_delay=500
                 , self_addr=None, deviceCategory='airconditioner.new', manufacture="HDiot",
                 deviceModel="KFR-50LW/10CBB23AU1"):
        self.LOG = logger
        self.sdk_obj = Wifi(logger=logger, time_delay=time_delay,
                            mac=mac, deviceCategory=deviceCategory, self_addr=self_addr, addr=addr,
                            manufacture=manufacture, deviceModel=deviceModel)
        self.sdk_obj.sim_obj = self
        self.need_stop = False

        # state data:
        self.task_obj = Task('Washer-task', self.LOG)
        self.create_tasks()
        self.alarm_dict = defaultdict(dict)
        self.attr_dict = defaultdict(dict)  # add by zx 20180524

    @need_add_lock(status_lock)
    def set_item(self, item, value):
        if item in self.__dict__:
            self.__dict__[item] = value
        else:
            self.LOG.error("Unknow item: %s" % (item))

    # add by zx 20180524
    @need_add_lock(status_lock)
    def get_item(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            self.LOG.error("get_item Unknown item: %s" % (item))

    @need_add_lock(status_lock)
    def add_item(self, item, value):
        try:
            setattr(self, item, value)
        except:
            self.LOG.error("add item fail: %s" % (item))

    def status_show(self):
        for item in sorted(self.__dict__):
            if item.startswith('_'):
                self.LOG.warn("%s: %s" % (item, str(self.__dict__[item])))

    def send_msg(self, msg):
        return self.sdk_obj.add_send_data(self.sdk_obj.msg_build(msg))

    @abstractmethod
    def protocol_handler(self, msg):
        pass

    def stop(self):
        self.need_stop = True
        self.sdk_obj.stop()
        if self.task_obj:
            self.task_obj.stop()
        self.LOG.warn('Thread %s stoped!' % (__name__))

    def run_forever(self):
        thread_list = []
        thread_list.append([self.sdk_obj.schedule_loop])
        thread_list.append([self.sdk_obj.send_data_loop])
        thread_list.append([self.sdk_obj.recv_data_loop])
        thread_list.append([self.sdk_obj.heartbeat_loop, False])
        thread_list.append([self.task_obj.task_proc])
        thread_list.append([self.alarm_proc])
        thread_ids = []
        for th in thread_list:
            thread_ids.append(threading.Thread(target=th[0], args=th[1:]))

        for th in thread_ids:
            th.setDaemon(True)
            th.start()

    def create_tasks(self):
        self.task_obj.add_task(
            'status maintain', self.status_maintain, 10000000, 100)

        self.task_obj.add_task('monitor event report',
                               self.status_report_monitor, 10000000, 1)

    def status_maintain(self):
        pass

    def status_report_monitor(self):
        need_send_report = False
        if not hasattr(self, 'old_status'):
            self.old_status = defaultdict(lambda: {})
            for item in self.__dict__:
                if item.startswith('_'):
                    self.LOG.yinfo("need check item: %s" % (item))
                    self.old_status[item] = copy.deepcopy(self.__dict__[item])

        for item in self.old_status:
            if self.old_status[item] != self.__dict__[item]:
                need_send_report = True
                self.old_status[item] = copy.deepcopy(self.__dict__[item])

        if need_send_report:
            self.send_msg(self.get_event_report())

    def alarm_proc(self):
        while self.need_stop == False:
            alarm_lock.acquire()
            for alarm in self.alarm_dict:
                if self.alarm_dict[alarm]['status'] == 'ready':
                    self.alarm_dict[alarm]['status'] = "over"
                    self.send_msg(self.alarm_report(self.alarm_dict[alarm]['error_code'], self.alarm_dict[alarm]
                    ['error_status'], self.alarm_dict[alarm]['error_level'], self.alarm_dict[alarm]['error_msg']))

                elif self.alarm_dict[alarm]['status'] == 'over':
                    pass

            alarm_lock.release()
            time.sleep(3)

    def alarm_report(self, error_code, error_status, error_level=1, error_msg="test alarm"):
        report_msg = {
            "method": "alarm",
            "attribute": {
                "error_code": error_code,
                "error_msg": error_msg,
                "error_level": error_level,
                "error_status": error_status,
            }
        }
        return json.dumps(report_msg)


    def new_alarm_report(self, attrDict):
        report_msg = {
            "method": "alarm",
            "attribute": attrDict
        }
        return json.dumps(report_msg)

    @need_add_lock(alarm_lock)
    def add_alarm(self, error_code, error_status, error_level=1, error_msg="test alarm"):
        if error_code in self.alarm_dict and self.alarm_dict[error_code]['status'] != 'over':
            pass
        else:
            self.alarm_dict[error_code]['error_code'] = error_code
            self.alarm_dict[error_code]['error_status'] = error_status
            self.alarm_dict[error_code]['error_level'] = error_level
            self.alarm_dict[error_code]['error_msg'] = error_msg
            self.alarm_dict[error_code]['status'] = 'ready'

    @need_add_lock(alarm_lock)
    def set_alarm(self, error_code, status):
        if error_code in self.alarm_dict:
            self.alarm_dict[error_code]['status'] = status
        else:
            self.LOG.error('error code not exist!')

    def alarm_confirm_rsp(self, req, error_code):
        self.LOG.warn(("故障(解除)上报确认:").encode(coding))
        self.set_alarm(error_code, 'over')
        rsp_msg = {
            "method": "dm_set",
            "req_id": req,
            "msg": "success",
            "code": 0,
            "attribute": {
                "error_code": error_code,
                "error_status": self.alarm_dict[error_code]["error_status"]
            }
        }
        return json.dumps(rsp_msg)

    def dm_set_rsp(self, req):
        rsp_msg = {
            "method": "dm_set",
            "req_id": req,
            "msg": "success",
            "code": 0
        }
        return json.dumps(rsp_msg)

    # add by zx-20180524
    def initAttrAndDict(self, initAttr=True, initDict=True):
        dictTmp = defaultdict(dict)
        sourceDict = self.attr_dict
        if sourceDict:
            for key, value in sourceDict.items():
                item_name = "_" + key
                if (initAttr):
                    self.add_item(item_name, value)
                # setattr(self, "_" + key, value)
                if (initDict):
                    dictTmp[key] = self.get_item(item_name)
        return dictTmp

class BaseZigbeeSim():
    __metaclass__ = ABCMeta
    status_lock = threading.Lock()

    def __init__(self, logger):
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        self.reportbeat_interval = 100

        # state data:
        self.report_seq = b'\x01'
        self.task_obj = Task('common-task', self.LOG)
        self.create_tasks()

    need_add_lock(status_lock)
    def set_item(self, item, value):
        if item in self.__dict__:
            self.__dict__[item] = value
        else:
            self.LOG.error("Unknow item: %s" % (item))

    need_add_lock(status_lock)
    def add_item(self, item, value):
        try:
            setattr(self, item, value)
        except:
            self.LOG.error("add item fail: %s" % (item))

    def status_show(self):
        for item in sorted(self.__dict__):
            if item.startswith('_'):
                self.LOG.warn("%s: %s" % (item, str(self.__dict__[item])))

    def send_msg(self, msg):
        return self.sdk_obj.add_send_data(self.sdk_obj.msg_build(msg))

    @abstractmethod
    def protocol_handler(self, msg, ack=False):
        pass

    def stop(self):
        self.need_stop = True
        #self.sdk_obj.stop()
        #if self.task_obj:
        #    self.task_obj.stop()
        self.LOG.warn('Thread %s stoped!' % (__name__))

    def run_forever(self):
        thread_list = []
        thread_list.append([self.task_obj.task_proc])
        thread_list.append([self.status_report_monitor])
        thread_list.append([self.reportAsHeartbeat])
        thread_ids = []
        for th in thread_list:
            thread_ids.append(threading.Thread(target=th[0], args=th[1:]))

        for th in thread_ids:
            th.setDaemon(True)
            th.start()

    def reportAsHeartbeat(self):
        while self.need_stop == False:
            if(self.addr == b''):
                pass
            else:
                self.LOG.warn("To send {0} heartBeat[dev_addr:{1}]".format(self.__class__.__name__,
                                                                            binascii.hexlify(self.addr)))
                self.event_report_proc("_Switch")
            time.sleep(self.reportbeat_interval)

    def create_tasks(self):
        self.task_obj.add_task(
            'status maintain', self.status_maintain, 10000000, 1)

        # self.task_obj.add_task('monitor event report',
        #                       self.status_report_monitor, 10000000, 1)

    def status_maintain(self):
        pass

    def status_report_monitor(self):
        while self.need_stop == False:
            need_send_report = []
            if not hasattr(self, 'old_status'):
                self.old_status = defaultdict(lambda: {})
                for item in self.__dict__:
                    if item.startswith('_'):
                        self.LOG.yinfo("need check item: %s" % (item))
                        self.old_status[item] = copy.deepcopy(
                            self.__dict__[item])

            for item in self.old_status:
                if self.old_status[item] != self.__dict__[item]:
                    need_send_report.append(item)
                    self.old_status[item] = copy.deepcopy(self.__dict__[item])

            for item in need_send_report:
                self.LOG.warn('Device report: %s' % (item))
                self.event_report_proc(item)

    def get_default_response(self, datas):
        def_rsp = {
            'control': bit_set(datas['control'], 7),
            'seq': datas['seq'],
            'addr': self.sdk_obj.src_addr,
            'cmd': datas['cmd'],
            'reserve': b'',
            'data': b'',
        }
        return def_rsp

    def add_seq(self):
        seq = struct.unpack('B', self.report_seq)[0]
        seq += 1
        if seq >= 255:
            seq = 0
        #self.seq = struct.pack('B', seq)
        self.set_item("report_seq",struct.pack('B', seq))

    def set_seq(self, seq):
        self.seq = seq

    def convert_to_dictstr(self, src):
        ret_str = ''
        ret_str += '\n{\n'
        for item in src:
            ret_str += protocol_data_printB(src[item],
                                            title="    %s," % (item))
            ret_str += '\n'
        ret_str += '}'
        return ret_str

    def get_event_report(self, req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10\x01'):
        self.add_seq()
        send_datas = {
            'control': b'\x00',
            'seq': self.report_seq,
            'addr': self.addr,
            'cmd': req_cmd_word,
            'reserve': b'',
            'data': data,
        }

        return send_datas

class Curtain(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Curtain, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self.switch = 99
        self._percent_lift = 1
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x02'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def reportAsHeartbeat(self):
        while self.need_stop == False:
            if(self.addr == b''):
                pass
            else:
                self.LOG.warn("To send {0} heartBeat[dev_addr:{1}]".format(self.__class__.__name__,
                                                                            binascii.hexlify(self.addr)))
                self.event_report_proc("_percent_lift")
            time.sleep(self.reportbeat_interval)

    def update_percent_lift(self, action):
        if action == 'close':
            if self._percent_lift > 1:
                self._percent_lift -= 10
            else:
                pass
        else:
            if self._percent_lift < 100:
                if self._percent_lift == 91:
                    self._percent_lift =100
                else:
                    self._percent_lift += 10
            else:
                pass

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    'data': b'\x00' + b'\x42' + b'\x05' + 'dooya' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0d' + 'onoff_curtain',
                },

                b'\x02\x01': {
                    'cmd': b'\x01\x02\x01' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x20' + b'\x01' + b'\x88',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x02\x01': {
                    'cmd': b'\x07\x02\x01' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('switch', 1)
                    self.task_obj.del_task('close')
                    self.task_obj.add_task(
                        'open', self.update_percent_lift, 10, 50, 'open')

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('switch', 0)
                    self.task_obj.del_task('open')
                    self.task_obj.add_task(
                        'close', self.update_percent_lift, 10, 50, 'close')

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('switch', 2)
                    self.task_obj.del_task('close')
                    self.task_obj.del_task('open')

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.task_obj.del_task('close')
                    self.task_obj.del_task('open')
                    self.set_item('_percent_lift', struct.unpack(
                        'B', datas['data'][:])[0])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='What is the fuck cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                    rsp_datas['cmd'] = rsp_data[b'\x02\x01']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x02\x01']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x02\x01':
                    rsp_datas['cmd'] = rsp_data[b'\x02\x01']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x02\x01']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_percent_lift':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x02\x01' + b'\x08\x00',
                                                       data=b'\x20' + struct.pack('B', self._percent_lift)))

        else:
            pass

class Led(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Led, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x00\x00'
        self._Hue = b''
        self.Saturation = b''
        self._Color_X = b'\x66\x2d'
        self._Color_Y = b'\xdf\x5c'
        self._Color_Temperature = b'\xdd\x00'
        self._Level = b'\x00\x00'
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x05'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_RGB_LedStrip',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Switch[0:0 + 1],
                },

                b'\x08\x00': {
                    'cmd': b'\x01\x08\x00\x00\x00',
                    'data': b'\x00' + b'\x20' + b'\x01' + self._Level[0:0 + 1],
                },

                b'\x00\x03': {
                    'cmd': b'\x01\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x21' + b'\x04' + self._Color_X + self._Color_Y,
                },
                'default': {
                    'cmd': b'\x01\x00\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x08\x00': {
                    'cmd': b'\x07\x08\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x00\x03': {
                    'cmd': b'\x07\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')
                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')
                else:
                    self.set_item('_Switch', b'\x02')

            elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                if datas['cmd'][3:3 + 2] == b'\x06\x00':
                    self.set_item('_Hue', datas['data'][0:0 + 1])
                    self.set_item('Saturation', datas['data'][1:1 + 1])

                elif datas['cmd'][3:3 + 2] == b'\x07\x00':
                    self.set_item('_Color_X', datas['data'][0:0 + 2])
                    self.set_item('_Color_Y', datas['data'][2:2 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x0a\x00':
                    self.set_item('_Color_Temperature', datas['data'][0:0 + 2])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                self.set_item('_Level', datas['data'][0:0 + 1])

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']
                #add by -zx for cmd:00 00 03 03 00 and 00 00 03 04 00
                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Color_Temperature' or req_cmd_word == '_Color_X':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x00\x03' + b'\x04\x00',
                                                       data=b'\x21' + self._Color_Y + b'\x03\x00' +
                                                       b'\x21' + self._Color_X + b'\x07\x00' +
                                                       b'\x21' + self._Color_Temperature))

        elif req_cmd_word == '_Level':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x08\x00' + b'\x00\x00', data=b'\x20' + self._Level))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class Switch(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Switch, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x08'
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x08'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                #'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
                'data': b'\x00' + self.Short_id + b'\x03\x01' + b'\x02\x03',
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    'data': b'\x00' + b'\x42' + b'\x0a' + 'EverGrande' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'BH-SZ103',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + b'\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')

                elif datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                else:
                    self.LOG.error("Fuck Configure reporting response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class Tube_lamp(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Tube_lamp, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x00\x00'
        self._Hue = b''
        self.Saturation = b''
        self._Color_X = b'\x66\x2d'
        self._Color_Y = b'\xdf\x5c'
        self._Color_Temperature = b'\xdd\x00'
        self._Level = b'\x00\x00'
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x05'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x19' + 'PAK_Dimmable_downlight_7W',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Switch[0:0 + 1],
                },

                b'\x08\x00': {
                    'cmd': b'\x01\x08\x00\x00\x00',
                    'data': b'\x00' + b'\x20' + b'\x01' + self._Level[0:0 + 1],
                },

                b'\x00\x03': {
                    'cmd': b'\x01\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x21' + b'\x04' + self._Color_X + self._Color_Y,
                },
                'default': {
                    'cmd': b'\x01\x00\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x08\x00': {
                    'cmd': b'\x07\x08\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x00\x03': {
                    'cmd': b'\x07\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')
                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')
                else:
                    self.set_item('_Switch', b'\x02')

            elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                if datas['cmd'][3:3 + 2] == b'\x06\x00':
                    self.set_item('_Hue', datas['data'][0:0 + 1])
                    self.set_item('Saturation', datas['data'][1:1 + 1])

                elif datas['cmd'][3:3 + 2] == b'\x07\x00':
                    self.set_item('_Color_X', datas['data'][0:0 + 2])
                    self.set_item('_Color_Y', datas['data'][2:2 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x0a\x00':
                    self.set_item('_Color_Temperature', datas['data'][0:0 + 2])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                self.set_item('_Level', datas['data'][0:0 + 1])

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']
                #add by -zx for cmd:00 00 03 03 00 and 00 00 03 04 00
                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Color_Temperature' or req_cmd_word == '_Color_X':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x00\x03' + b'\x04\x00',
                                                       data=b'\x21' + self._Color_Y + b'\x03\x00' +
                                                       b'\x21' + self._Color_X + b'\x07\x00' +
                                                       b'\x21' + self._Color_Temperature))

        elif req_cmd_word == '_Level':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x08\x00' + b'\x00\x00', data=b'\x20' + self._Level))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class Shoot_lamp(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Shoot_lamp, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x00\x00'
        self._Hue = b''
        self.Saturation = b''
        self._Color_X = b'\x66\x2d'
        self._Color_Y = b'\xdf\x5c'
        self._Color_Temperature = b'\xdd\x00'
        self._Level = b'\x00\x00'
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x05'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x1a' + 'PAK_Dimmable_spotlight_10W',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Switch[0:0 + 1],
                },

                b'\x08\x00': {
                    'cmd': b'\x01\x08\x00\x00\x00',
                    'data': b'\x00' + b'\x20' + b'\x01' + self._Level[0:0 + 1],
                },

                b'\x00\x03': {
                    'cmd': b'\x01\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x21' + b'\x04' + self._Color_X + self._Color_Y,
                },
                'default': {
                    'cmd': b'\x01\x00\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x08\x00': {
                    'cmd': b'\x07\x08\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x00\x03': {
                    'cmd': b'\x07\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')
                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')
                else:
                    self.set_item('_Switch', b'\x02')

            elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                if datas['cmd'][3:3 + 2] == b'\x06\x00':
                    self.set_item('_Hue', datas['data'][0:0 + 1])
                    self.set_item('Saturation', datas['data'][1:1 + 1])

                elif datas['cmd'][3:3 + 2] == b'\x07\x00':
                    self.set_item('_Color_X', datas['data'][0:0 + 2])
                    self.set_item('_Color_Y', datas['data'][2:2 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x0a\x00':
                    self.set_item('_Color_Temperature', datas['data'][0:0 + 2])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                self.set_item('_Level', datas['data'][0:0 + 1])

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']
                #add by -zx for cmd:00 00 03 03 00 and 00 00 03 04 00
                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Color_Temperature' or req_cmd_word == '_Color_X':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x00\x03' + b'\x04\x00',
                                                       data=b'\x21' + self._Color_Y + b'\x03\x00' +
                                                       b'\x21' + self._Color_X + b'\x07\x00' +
                                                       b'\x21' + self._Color_Temperature))

        elif req_cmd_word == '_Level':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x08\x00' + b'\x00\x00', data=b'\x20' + self._Level))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class Banded_lamp(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Banded_lamp, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x00\x00'
        self._Hue = b''
        self.Saturation = b''
        self._Color_X = b'\x66\x2d'
        self._Color_Y = b'\xdf\x5c'
        self._Color_Temperature = b'\xdd\x00'
        self._Level = b'\x00\x00'
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x05'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_RGB_LedStrip',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Switch[0:0 + 1],
                },

                b'\x08\x00': {
                    'cmd': b'\x01\x08\x00\x00\x00',
                    'data': b'\x00' + b'\x20' + b'\x01' + self._Level[0:0 + 1],
                },

                b'\x00\x03': {
                    'cmd': b'\x01\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x21' + b'\x04' + self._Color_X + self._Color_Y,
                },
                'default': {
                    'cmd': b'\x01\x00\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x08\x00': {
                    'cmd': b'\x07\x08\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x00\x03': {
                    'cmd': b'\x07\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')
                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')
                else:
                    self.set_item('_Switch', b'\x02')

            elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                if datas['cmd'][3:3 + 2] == b'\x06\x00':
                    self.set_item('_Hue', datas['data'][0:0 + 1])
                    self.set_item('Saturation', datas['data'][1:1 + 1])

                elif datas['cmd'][3:3 + 2] == b'\x07\x00':
                    self.set_item('_Color_X', datas['data'][0:0 + 2])
                    self.set_item('_Color_Y', datas['data'][2:2 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x0a\x00':
                    self.set_item('_Color_Temperature', datas['data'][0:0 + 2])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                self.set_item('_Level', datas['data'][0:0 + 1])

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']
                #add by -zx for cmd:00 00 03 03 00 and 00 00 03 04 00
                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Color_Temperature' or req_cmd_word == '_Color_X':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x00\x03' + b'\x04\x00',
                                                       data=b'\x21' + self._Color_Y + b'\x03\x00' +
                                                       b'\x21' + self._Color_X + b'\x07\x00' +
                                                       b'\x21' + self._Color_Temperature))

        elif req_cmd_word == '_Level':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x08\x00' + b'\x00\x00', data=b'\x20' + self._Level))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class Celling_lamp(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(Celling_lamp, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Switch = b'\x00\x00'
        self._Hue = b''
        self.Saturation = b''
        self._Color_X = b'\x66\x2d'
        self._Color_Y = b'\xdf\x5c'
        self._Color_Temperature = b'\xdd\x00'
        self._Level = b'\x00\x00'
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x05'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x1e' + 'PAK_Dimmable_celling_light_28W',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Switch[0:0 + 1],
                },

                b'\x08\x00': {
                    'cmd': b'\x01\x08\x00\x00\x00',
                    'data': b'\x00' + b'\x20' + b'\x01' + self._Level[0:0 + 1],
                },

                b'\x00\x03': {
                    'cmd': b'\x01\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00' + b'\x21' + b'\x04' + self._Color_X + self._Color_Y,
                },
                'default': {
                    'cmd': b'\x01\x00\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x06\x00': {
                    'cmd': b'\x07\x06\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x08\x00': {
                    'cmd': b'\x07\x08\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                b'\x00\x03': {
                    'cmd': b'\x07\x00\x03' + self.cmd[3:3 + 2],
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07\x00\x00\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x06\x00':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Switch', b'\x00')
                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Switch', b'\x01')
                else:
                    self.set_item('_Switch', b'\x02')

            elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                if datas['cmd'][3:3 + 2] == b'\x06\x00':
                    self.set_item('_Hue', datas['data'][0:0 + 1])
                    self.set_item('Saturation', datas['data'][1:1 + 1])

                elif datas['cmd'][3:3 + 2] == b'\x07\x00':
                    self.set_item('_Color_X', datas['data'][0:0 + 2])
                    self.set_item('_Color_Y', datas['data'][2:2 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x0a\x00':
                    self.set_item('_Color_Temperature', datas['data'][0:0 + 2])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                self.set_item('_Level', datas['data'][0:0 + 1])

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']
                #add by -zx for cmd:00 00 03 03 00 and 00 00 03 04 00
                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x08\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x08\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x08\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x00\x03':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x03']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x03']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Switch':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x06\x00' + b'\x00\x00', data=b'\x10' + self._Switch))

        elif req_cmd_word == '_Color_Temperature' or req_cmd_word == '_Color_X':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x00\x03' + b'\x04\x00',
                                                       data=b'\x21' + self._Color_Y + b'\x03\x00' +
                                                       b'\x21' + self._Color_X + b'\x07\x00' +
                                                       b'\x21' + self._Color_Temperature))

        elif req_cmd_word == '_Level':
            return self.send_msg(self.get_event_report(req_cmd_word=b'\x0a' + b'\x08\x00' + b'\x00\x00', data=b'\x20' + self._Level))

        elif req_cmd_word == '_Window_covering':
            pass

        else:
            pass

class DoorLock(BaseZigbeeSim):
    def __init__(self, logger, mac=b'123456', short_id=b'\x11\x11', Endpoint=b'\x01'):
        super(DoorLock, self).__init__(logger=logger)
        self.LOG = logger
        self.sdk_obj = None
        self.need_stop = False

        # state data:
        self._Lockstatus = b'\x01'
        self.Saturation = b''
        self._Window_covering = b''
        self.Percentage_Lift_Value = b''
        self.Short_id = short_id
        self.Endpoint = Endpoint
        self.mac = str(mac) + b'\x00' * (8 - len(str(mac)))
        self.Capability = b'\x01'
        self.seq = b'\x01'
        self.cmd = b''
        self.addr = b''

    def reportAsHeartbeat(self):
        while self.need_stop == False:
            if(self.addr == b''):
                pass
            else:
                self.LOG.warn("To send {0} heartBeat[dev_addr:{1}]".format(self.__class__.__name__,
                                                                            binascii.hexlify(self.addr)))
                self.event_report_proc("_Lockstatus")
            time.sleep(self.reportbeat_interval)

    def get_cmd(self, cmd):
        cmds = {
            'Device Announce': {
                'cmd': b'\x40\x13\x00\x00\x00',
                'data': self.Short_id + self.mac + self.Capability,
            },

            'Active Endpoint Response': {
                'cmd': b'\x40\x05\x80\x00\x00',
                'data': b'\x00' + self.Short_id + b'\x01' + self.Endpoint,
            },

            'Leave response': {
                'cmd': b'\x40\x34\x80\x01\x00',
                'data': b'\x00',
            },

            'Read attribute response': {
                b'\x00\x00': {
                    'cmd': b'\x01\x00\x00\x04\x00',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'PAK' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x16' + 'PAK_Dimmable_downlight',
                    #'data': b'\x00' + b'\x42' + b'\x03' + 'LDS' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x0e' + 'ZHA-ColorLight',
                    'data': b'\x00' + b'\x42' + b'\x04' + 'bida' + b'\x05\x00' + b'\x00' + b'\x42' + b'\x08' + 'doorlock',
                },

                b'\x06\x00': {
                    'cmd': b'\x01\x06\x00\x00\x00',
                    'data': b'\x00' + b'\x10' + b'\x01' + self._Lockstatus[0:0 + 1],
                },

                b'\x01\x00\x21\x00': {
                    'cmd': b'\x01\x01\x00\x21\x00',
                    'data': b'\x00\x20\xa0'
                },

                b'\x01\x01\x82\x00': {
                    'cmd': b'\x01\x01\x01\x82\x00',
                    'data': b'\x00\x20\x00'
                },

                'default': {
                    'cmd': b'\x01' + self.cmd[1:1+4],
                    'data': b'\x00' + b'\x10' + b'\x01\x00',
                },
            },

            'Bind response': {
                'cmd': b'\x40\x21\x80\x00\x00',
                'data': b'\x00',
            },

            'Configure reporting response': {
                b'\x01\x00':{
                    'cmd':b'\x07\x01\x00\x00\x00',
                    'data':b'\x00\x00'
                    },
                b'\x01\x01': {
                    'cmd': b'\x07\x01\x01\x00\x00',
                    'data': b'\x00\x00\x00\x00',
                },

                'default': {
                    'cmd': b'\x07' + self.cmd[1:1+2] + b'\x00\x00',
                    'data': b'\x00\x00',
                },
            },

            'Onoff Lock Response': {
                'cmd': b'\x4a\x01\x01\x00\x00',
                'data': b'\x01\x02\xff\xff\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00'
            },
        }
        return cmds.get(cmd, None)

    def protocol_handler(self, datas, ack=False):
        need_ASP_response = False
        need_default_response = False
        rsp_datas = {
            'control': datas['control'],
            'seq': datas['seq'],
            'addr': datas['addr'],
            'cmd': b'\x0B' + datas['cmd'][1:],
            'reserve': datas['reserve'],
            'data': b'\x81',
        }
        if bit_get(datas['control'], 7):
            self.LOG.debug('ACK msg!')
            return
        else:
            self.LOG.info("recv msg: " + self.convert_to_dictstr(datas))
            self.send_msg(self.get_default_response(datas))
            self.set_seq(datas['seq'])
            self.addr = datas['addr']
            self.cmd = datas['cmd']

        req_cmd_type = datas['cmd'][0:0 + 1]
        req_cmd_domain = datas['cmd'][1:1 + 2]
        req_cmd_word = datas['cmd'][3:3 + 2]

        if datas['cmd'][:1] == b'\x40':
            if datas['cmd'][1:] == b'\x36\x00\x00\x00':
                rsp_data = self.get_cmd('Device Announce')
                if rsp_data:
                    rsp_datas['control'] = datas['control']
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x05\x00\x00\x00':
                self.Endpoint = b'\x01'
                rsp_data = self.get_cmd('Active Endpoint Response')
                #self.set_item('Short_id', datas['data'])
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x34\x00\x01\x00':
                self.sdk_obj.set_work_status(False)
                rsp_data = self.get_cmd('Leave response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            elif datas['cmd'][1:] == b'\x21\x00\x00\x00':
                #self.set_item('mac', datas['data'][0:0 + 8])
                #self.set_item('endpoint', datas['data'][8:8 + 1])
                #self.set_item('Short_id', datas['data'][9:9 + 2])
                rsp_data = self.get_cmd('Bind response')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:], title='Unknow cmd:'))

        elif datas['cmd'][:1] == b'\x41':
            if datas['cmd'][1:1 + 2] == b'\x01\x01':
                rsp_data = self.get_cmd('Onoff Lock Response')
                if datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Lockstatus', b'\x02')
                    self.task_obj.add_task(
                        'autoclosedoor', self.set_item, 1, 300, '_Lockstatus',b'\x01')
                elif datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Lockstatus', b'\x01')
                if rsp_data:
                    rsp_datas['cmd'] = rsp_data['cmd']
                    rsp_datas['data'] = rsp_data['data']
                else:
                    pass
                return rsp_datas

            elif datas['cmd'][1:1 + 2] == b'\x02\x01':
                if datas['cmd'][3:3 + 2] == b'\x00\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x01\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x02\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])

                elif datas['cmd'][3:3 + 2] == b'\x05\x00':
                    self.set_item('_Window_covering', datas['cmd'][3:3 + 2])
                    self.set_item('Percentage_Lift_Value',
                                  datas['data'][0:0 + 1])

                else:
                    self.LOG.error(protocol_data_printB(
                        datas['cmd'][3:3 + 2], title='Unknow cmd:'))

            else:
                self.LOG.error(protocol_data_printB(
                    datas['cmd'][1:1 + 2], title='Unknow cmd:'))

            return

        elif datas['cmd'][:1] == b'\x00':
            rsp_data = self.get_cmd('Read attribute response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x00\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x00\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x00\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x06\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x06\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x06\x00']['data']

                elif datas['cmd'][1:1 + 4] == b'\x01\x00\x21\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x01\x00\x21\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x01\x00\x21\x00']['data']

                elif datas['cmd'][1:1 + 4] == b'\x01\x01\x82\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x01\x01\x82\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x01\x01\x82\x00']['data']

                else:
                    self.LOG.error("Fuck Read attribute response")
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        elif datas['cmd'][:1] == b'\x06':
            self.sdk_obj.set_work_status(False)
            rsp_data = self.get_cmd('Configure reporting response')
            if rsp_data:
                if datas['cmd'][1:1 + 2] == b'\x01\x00':
                    rsp_datas['cmd'] = rsp_data[b'\x01\x00']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x01\x00']['data']

                elif datas['cmd'][1:1 + 2] == b'\x01\x01':
                    rsp_datas['cmd'] = rsp_data[b'\x01\x01']['cmd']
                    rsp_datas['data'] = rsp_data[b'\x01\x01']['data']

                else:
                    rsp_datas['cmd'] = rsp_data['default']['cmd']
                    rsp_datas['data'] = rsp_data['default']['data']

            else:
                pass

        else:
            self.LOG.error("What is the fuck msg?")
            return

        self.LOG.yinfo("send msg: " + self.convert_to_dictstr(rsp_datas))
        return rsp_datas

    def event_report_proc(self, req_cmd_word):
        if req_cmd_word == '_Lockstatus':
            cmd = b'\x0a\x01\x01\x00\x00'
            dataEnd = b'\x15'
            if self._Lockstatus == b'\x01':
                dataEnd = '\x13'
            if self._Lockstatus == b'\x02':
                dataEnd = '\x15'
            data_tmp = b'\x30' + self._Lockstatus + b'\x80\x00\x21\xff' + dataEnd
            return self.send_msg(self.get_event_report(req_cmd_word=cmd, data=data_tmp))

        else:
            pass


def Load_zb_ini_file(zb_obj=None, loadfile=False, fileName=get_zb_save_dev_file()):
    '''This function shoud used before zb_obj.run_forever()'''
    if loadfile and zb_obj:
        cf = ConfigParser.ConfigParser()
        epArr = (b'\x00', b'\x01', b'\x02', b'\x03')
        if cf.read(fileName):
            for s in cf.sections():
                short_id = chr(int(s[0:2], 16)) + chr(int(s[2:4], 16))
                dev_type = cf.get(s, "dev_type")
                dev_mac = cf.get(s, "dev_mac")
                epCount = 1
                zb_obj.set_device(eval(dev_type))
                if (dev_type == "Switch"):
                    epCount = 3
                for i in range(0, epCount + 1):
                    key = short_id + epArr[i]
                    if (i == 1):
                        key0 = short_id + epArr[0]
                        zb_obj.devices[key] = zb_obj.devices[key0]
                    else:
                        zb_obj.devices[key] = zb_obj.factory(logger=zb_obj.LOG, mac=dev_mac,
                                                             short_id=short_id, Endpoint=epArr[i])
                        if(i==0):
                            zb_obj.devices[key].addr = short_id + epArr[1]
                        else:
                            zb_obj.devices[key].addr = key
                        zb_obj.devices[key].sdk_obj = zb_obj
                        zb_obj.devices[key].run_forever()



if __name__ == '__main__':
    pass
