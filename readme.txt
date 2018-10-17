testtool:	原始的文件结构，0706版本后基本不进行维护，除0814由于紧急需求临时修改了部分文件
TT_V2	:	按意见优化的文件结构，主要去除了重复代码和一些暂未使用的代码，在testtool0706版本基础上进行更新

test_tool:
orgin   :       orgin version
0529    :       1) 修改默认COM口为3
                2) 修改Start_sim不启动ZigBee并HoldOn在WIFI
                3) 新增WIFI设备支持不重启模拟器删除后重新添加
0601    :       1)wifi_device.py 支持WIFI模拟器绑定本地socket连接和端口
                2)zb_dev_mul.py支持--device指定启动设备和--interval指定轮询时间
                3)zb_devices.py LED支持0000030300 0000030400命令的response
0615    :       1)支持孙亚坤的多网卡测试版本，和0601区别不大
0625    ：      1)新增了按照SSID和PWD自动连接WIFI的脚本
0628    :       1)WIFI协议新增0.4.5AI路由器的getmsgcode变更
                2)WIFI子设备的WIFI构造函数下沉到基类
                3)新增AirSimuCmd用于本地操控Air设备并能上报到APP中
0702	:		1)zb_devices.py:LED中LDS改为PAK灯带
				2)wifi_max_conn.py:新增自动断开/连接WIFI的功能
				3)basic.BasicSimuCmd.py:新增基类支持各种WIFI设备CMD
				4)AirSimuCmd.py:新增空调控制台脚本用于模拟空调和本地操作
				5)wifi_protocol.py:正式修改WIFI协议[-2:]为[4:6]
0705	:		1)修改4文件版本前备份
0706	:		1)修改部分错误消息后的备份
0814	:	1)修改了Start_sim逻辑MAC固定且启动数目可配

TT_V2	:
0709	:	1)新增IPC和WIFI窗帘模拟
0710	:	1)新增电饭锅开关灯空气指示仪温湿仪等5个WIFI设备
0711	:	1)新增基类中新格式告警
		2)新增模拟器：门窗传感器，人体传感器，可视对讲，音箱，门锁，可视门铃
0719	:	1)Zigbee新增窗帘灯开关初始代码
		2)Socket新增绑定线程锁代码
0720	:	1)新增4种灯
		2)洗衣机空调dm_set补全
0720a	:	1)新增门锁框架
		2)新增EXE封装后LOG替换字符串代码
0725	:	1)WIFI设备MAC地址格式修正
		2)修复WIFI设备洗衣机，空净和ZB设备灯的BUG
		3)WIFI设备加入配置文件wifi_devices.conf
		4)ZB设备窗帘CMD新增控制命令
0726	:	1)门锁Model修改
		2）IPC的RTSP和回看消息补全
0730	:	1)Zigbee添加配置文件
		2)WIFI设备MAC修改为6个Byte
0730a	:	1)门锁开关锁上报和LockStatus新增，未验证
		2)开关加上3个EndPoint的Logic，未验证
		3)IPC的RSTP服务器放入配置文件中1.0.2_442可以添加,仍然没有图像
0802	:	1)IPC可视门铃调整消息结构，IPC暂不支持APP直播回看
		2)配置文件值微调，适应ffmpeg+EasyDrawing+VLC播放
		3)移植批量WIFI和ZB设备的脚本，文件名不变
0814	:	1)修改了Start_sim逻辑MAC固定且启动数目可配
0821	:	1)修改了MAC必须为0-F的字符串，最多12对应48BIT
		2)修改了空调晾衣杆空净水净洗衣机的MODEL避免其被识别成空调，针对硬测0.6.2测试+1.1.1_68通过
0822	:	1)修改COM口打印数据的级别，取消NoTask和DirtyData的丢弃打印
		2)修改窗帘上报间隔为0.5S，粒度为10%,修复一个新版路由器会导致窗帘序列号错误的问题
0827	:	1)修复一个Windows下控制台打印使能不生效的BUG
		2)取消原心跳进程，加上设备MAC不随机的预研代码
		3)新增周期性上报状态以充当心跳报文
0829	:	1)Zigbee支持从配置文件中添加设备，默认协议中路由器地址字段为b'\x00\x00\x01'
		2)修复ZigBee中Stop会导致所有ZigBee设备无法收发的问题
0830	:	1)修复WIFI设备由于路径问题可能导致BVT测试中配置文件无法读取的问题
		2)ZigBee子设备取消基类中的状态变更和任务轮询代码，改为每次SetItem后上报，仅保留心跳，窗帘完全保留
		3)zb_dev.ini新增mac_desc增强可读性
0904	:	1)修复Stop后由于没有关闭Socket可能导致服务器永久在线的BUG
0907	:	1)ZB设备的mac_desc加入正则匹配替换
0910	:	1)IPC误认为空调的BUG修正
0919	:	1)修复在0.7.1上因为子设备类型不匹配导致除空调外WIFI设备无法添加的问题
		2)修复开关和窗帘读属性没有默认值的KEY导致失败的问题
		3)针对2的问题优化了LOG显示，现在会打印出完整的CMD
0925	:	1)对于TaskProc函数中的异常会记录LOG后不再抛出，此修改是为了适配ATC在调用stop后会打印异常信息，对用例通过率有影响
1016	:	1)提升连接成功和设置工厂成功的日志级别为WARN
		2)默认批量启动的脚本在运行时先删除之前LOG
		3)start_sim新增默认不启动的press any key才启动Socket连接的功能,加入MAC地址写入LOG，默认每次启动各1台
		4)3提到的默认不启动可以使用py -2 start_sim manu使得启动，17号修改，由于1016版本未发，此修改并入1016版本,此文档加入Git