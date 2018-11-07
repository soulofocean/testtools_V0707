# -*- encoding:UTF-8 -*-
import sys
import os
reload(sys)
sys.setdefaultencoding('utf8')
from AirSimuCmd import Air
from HangerSimuCmd import Hanger
from WaterFilterSimuCmd import Waterfilter
from AirFilterSimuCmd import AirFilter
from WasherSimuCmd import Washer
from  os.path import join
from basic.BasicCommon import *
import time
import random
Dict_sim =\
    {
        'air': 1,
        'hanger':1,
        'waterfilter':1,
        'airfilter':1,
        'washer':1
    }
rout_addr = "192.168.10.1"

device_online_list=[]
mac_sample_str="1234567890abcdef"
Sim=''
useRandomMac = False
rm_log = True
def start_sim(manu = False):
    totalcount = 0
    for cnt in Dict_sim.values():
        totalcount += cnt
    if(totalcount > 128):
        print ("Device total count should less than 129:[now is %d]" % (totalcount,))
        sys.exit(-666)
    #macTmp = ''.join(random.sample(mac_sample_str, 6))
    macTmp = ''
    clevel = logging.WARN
    rlevel = logging.INFO
    for sim_name, sim_cnt in Dict_sim.items():
        if sim_name == 'air':
            for i in range(0,sim_cnt):
                if useRandomMac:
                    macTmp = ''.join(random.sample(mac_sample_str, 12))
                else:
                    macTmp = ("010%09d" % (i,))
                Log = MyLogger(join('log','%s%s.log' % (sim_name,i)), clevel=clevel, rlevel=rlevel)
                Sim = Air
                sim = Sim(logger=Log, mac=macTmp, addr=(rout_addr, 65381), time_delay=500)
                sim.run_forever()
                device_online_list.append(sim)
                if manu:
                    raw_input("Press any key to continue")
        elif sim_name == 'hanger':
            for i in range(0,sim_cnt):
                if useRandomMac:
                    macTmp = ''.join(random.sample(mac_sample_str, 12))
                else:
                    macTmp = ("020%09d" % (i,))
                Log = MyLogger(join('log', '%s%s.log' % (sim_name, i)), clevel=clevel, rlevel=rlevel)
                Sim = Hanger
                sim = Sim(logger=Log, mac=macTmp, addr=(rout_addr, 65381), time_delay=500)
                sim.run_forever()
                device_online_list.append(sim)
                if manu:
                    raw_input("Press any key to continue")
        elif sim_name == 'waterfilter':
            for i in range(0,sim_cnt):
                if useRandomMac:
                    macTmp = ''.join(random.sample(mac_sample_str, 12))
                else:
                    macTmp = ("030%09d" % (i,))
                Log = MyLogger(join('log', '%s%s.log' % (sim_name, i)), clevel=clevel, rlevel=rlevel)
                Sim = Waterfilter
                sim = Sim(logger=Log, mac=macTmp, addr=(rout_addr, 65381), time_delay=500)
                sim.run_forever()
                device_online_list.append(sim)
                if manu:
                    raw_input("Press any key to continue")
        elif sim_name == 'airfilter':
            for i in range(0,sim_cnt):
                if useRandomMac:
                    macTmp = ''.join(random.sample(mac_sample_str, 12))
                else:
                    macTmp = ("040%09d" % (i,))
                Log = MyLogger(join('log', '%s%s.log' % (sim_name, i)), clevel=clevel, rlevel=rlevel)
                Sim = AirFilter
                sim = Sim(logger=Log, mac=macTmp, addr=(rout_addr, 65381), time_delay=500)
                sim.run_forever()
                device_online_list.append(sim)
                if manu:
                    raw_input("Press any key to continue")
        elif sim_name == 'washer':
            for i in range(0,sim_cnt):
                if useRandomMac:
                    macTmp = ''.join(random.sample(mac_sample_str, 12))
                else:
                    macTmp = ("050%09d" % (i,))
                Log = MyLogger(join('log', '%s%s.log' % (sim_name, i)), clevel=clevel, rlevel=rlevel)
                Sim = Washer
                sim = Sim(logger=Log, mac=macTmp, addr=(rout_addr, 65381), time_delay=500)
                sim.run_forever()
                device_online_list.append(sim)
                if manu:
                    raw_input("Press any key to continue")

def hold_on():
    while True:
        time.sleep(1)

if __name__ =='__main__':
    logpath = "log"
    if rm_log and os.path.exists(logpath):
        for f in os.listdir(logpath):
            if ".log" in f and os.path.isfile(path=join(logpath,f)):
                os.remove(join(logpath,f))

    manu = "manu" in sys.argv
    start_sim(manu)
    #os.system('python zb_dev_multiple.py')
    hold_on()



