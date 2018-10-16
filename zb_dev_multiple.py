#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""sim
by Kobe Gong. 2018-01-29
"""


import argparse
import copy
import datetime
import decimal
import json
import logging
import os
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from cmd import Cmd
from collections import defaultdict


from basic.BasicSimuCmd import *


if sys.getdefaultencoding() != 'utf-8':
    reload(sys)
    sys.setdefaultencoding('utf-8')


class ArgHandle():
    def __init__(self):
        self.parser = self.build_option_parser("-" * 50)

    def build_option_parser(self, description):
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            '-d', '--debug',
            dest='debug',
            action='store_true',
            help='debug switch',
        )
        parser.add_argument(
            '-t', '--time-delay',
            dest='time_delay',
            action='store',
            default=0,
            type=int,
            help='time delay(ms) for msg send to server, default time is 0(ms)',
        )
        parser.add_argument(
            '-p', '--port',
            dest='serial_port',
            action='store',
            default='COM4',
            help='Specify serial port number',
        )
        parser.add_argument(
            '--device',
            dest='device_type',
            action='store',
            choices={'Tube_lamp', 'Shoot_lamp', 'Banded_lamp', 'Celling_lamp','DoorLock', 'Curtain', 'Switch'},
            default=['Tube_lamp', 'Shoot_lamp', 'Banded_lamp', 'Celling_lamp','DoorLock', 'Curtain', 'Switch'],
            #default='Switch',
            help="Specify device type: 'Led', 'Curtain', 'Switch'",
        )
        parser.add_argument(
            '--interval',
            dest='switch_interval',
            action='store',
            default=30,
            help="Switch different device interval default is 30s",
        )
        return parser

    def get_args(self, attrname):
        return getattr(self.args, attrname)

    def check_args(self):
        pass

    def run(self):
        self.args = self.parser.parse_args()
        cprint.notice_p("CMD line: " + str(self.args))
        self.check_args()


class MyCmd(Cmd):
    def __init__(self, logger, sim_objs=None):
        Cmd.__init__(self)
        self.prompt = "SIM>"
        self.sim_objs = sim_objs
        self.LOG = logger

    def help_log(self):
        cprint.notice_p(
            "change logger level: log {0:critical, 1:error, 2:warning, 3:info, 4:debug}")

    def do_log(self, arg, opts=None):
        level = {
            '0': logging.CRITICAL,
            '1': logging.ERROR,
            '2': logging.WARNING,
            '3': logging.INFO,
            '4': logging.DEBUG,
        }
        if int(arg) in range(5):
            for i in self.sim_objs:
                cprint.notice_p("-" * 20)
                self.sim_objs[i].LOG.set_level(level[arg])
        else:
            cprint.warn_p("unknow log level: %s!" % (arg))

    def help_st(self):
        cprint.notice_p("show state")

    def do_st(self, arg, opts=None):
        for i in self.sim_objs:
            cprint.notice_p("-" * 20)
            self.sim_objs[i].status_show()

    def help_set(self):
        cprint.notice_p("set state")

    def do_set(self, arg, opts=None):
        args = arg.split()
        for i in self.sim_objs:
            self.sim_objs[i].set_item(args[0], args[1])

    def default(self, arg, opts=None):
        try:
            subprocess.call(arg, shell=True)
        except:
            pass

    def emptyline(self):
        pass

    def help_exit(self):
        print("Will exit")

    def do_exit(self, arg, opts=None):
        cprint.notice_p("Exit CLI, good luck!")
        sys_cleanup()
        sys.exit()


def sys_proc(action="default"):
    global thread_ids
    thread_ids = []
    for th in thread_list:
        thread_ids.append(threading.Thread(target=th[0], args=th[1:]))

    for th in thread_ids:
        th.setDaemon(True)
        th.start()
        # time.sleep(0.1)


def sys_join():
    for th in thread_ids:
        th.join()


def sys_init():
    LOG.info("Let's go!!!")


def sys_cleanup():
    LOG.info("Goodbye!!!")

rm_log = True

if __name__ == '__main__':
    logpath = os.path.abspath(sys.argv[0]).replace('py', 'log').replace('exe','log')
    if rm_log and os.path.isfile(logpath) and os.path.exists(logpath):
        os.remove(logpath)
    LOG = MyLogger(logpath, clevel=logging.WARN,rlevel=logging.WARN)
    cprint = cprint(__name__)

    sys_init()

    arg_handle = ArgHandle()
    arg_handle.run()

    global thread_list
    thread_list = []

    sims = {}
    log_level = logging.DEBUG

    useFile = True
    zigbee_obj = ZIGBEE(arg_handle.get_args('serial_port'),
                        logger=LOG, time_delay=arg_handle.get_args('time_delay'),savefile=useFile)
    Load_zb_ini_file(zb_obj=zigbee_obj, loadfile=useFile)
    zigbee_obj.run_forever()
    sys_proc()
    device_list = arg_handle.get_args('device_type')
    # ['Tube_lamp', 'Shoot_lamp', 'Banded_lamp', 'Celling_lamp','DoorLock', 'Curtain', 'Switch']
    if isinstance(device_list, list):
        while True:
            for device_cls in device_list:
                Sim = eval(device_cls)
                zigbee_obj.set_device(Sim)
                time.sleep(arg_handle.get_args('switch_interval'))
    elif isinstance(device_list, str):
        Sim = eval(device_list)
        zigbee_obj.set_device(Sim)
    else:
        LOG.error("type of device_list is %s" % type(device_list))

    if arg_handle.get_args('debug'):
        dmsg = b'\x55\xaa\x10\x27\x01\x11\x22\x33\x77\x88\x99\x11\x33\x55\x66\x22\x88\x11\x11'
        time.sleep(1)
        zigbee_obj.queue_in.put(dmsg)

    if True:
        # signal.signal(signal.SIGINT, lambda signal,
        #              frame: cprint.notice_p('Exit SYSTEM: exit'))
        my_cmd = MyCmd(logger=LOG, sim_objs=zigbee_obj.devices)
        my_cmd.cmdloop()
    else:
        sys_join()
        sys_cleanup()
        sys.exit()
