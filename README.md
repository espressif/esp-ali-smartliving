# ESP 设备对接阿里云生活物联网平台 & 天猫精灵 IoT 开放平台
# 目录

- [0.介绍](#Introduction)  
- [1.目的](#aim)  
- [2.硬件准备](#hardwareprepare)  
- [3.生活物联网平台准备](#aliyunprepare)  
- [4.环境搭建](#compileprepare)  
- [5.SDK 准备](#sdkprepare)  
- [6.编译&烧写&运行](#makeflash)  

# <span id = "Introduction">0.介绍</span>
[乐鑫](https://www.espressif.com/zh-hans)是高集成度芯片的设计专家，专注于设计简单灵活、易于制造和部署的解决方案。乐鑫研发和设计 IoT 业内集成度高、性能稳定、功耗低的无线系统级芯片，乐鑫的模组产品集成了自主研发的系统级芯片，因此具备强大的 Wi-Fi 和蓝牙功能，以及出色的射频性能。

[生活物联网平台 SDK ](https://code.aliyun.com/living_platform/ali-smartliving-device-sdk-c.git)是阿里云 IoT 针对生活物联网平台所提供的设备端 SDK。SDK 基于 C 语言开发，代码开源，提供了 API 供您调用，用于实现与阿里云 IoT 平台通信以及其它的辅助功能（例如 WiFi 配网、本地控制等）。当前 ali-smartliving-device-sdk-c 是基于[ SDK 仓库](https://code.aliyun.com/living_platform/ali-smartliving-device-sdk-c.git), 分支 [rel_1.6.0](https://code.aliyun.com/living_platform/ali-smartliving-device-sdk-c/tree/rel_1.6.0) 进行开发。

# <span id = "aim">1.目的</span>
本文基于 linux 环境，介绍 ESP 设备对接阿里云生活物联网平台 & 天猫精灵 IoT 开放平台的具体流程，供读者参考。

# <span id = "hardwareprepare">2.硬件准备</span>
- **linux 环境**  
用来编译 & 烧写 & 运行等操作的必须环境。 
> windows 用户可安装虚拟机，在虚拟机中安装 linux。

- **ESP 设备**  
ESP 设备包括 [ESP芯片](https://www.espressif.com/zh-hans/products/hardware/socs)，[ESP模组](https://www.espressif.com/zh-hans/products/hardware/modules)，[ESP开发板](https://www.espressif.com/zh-hans/products/hardware/development-boards)等。

- **USB 线**  
连接 PC 和 ESP 设备，用来烧写/下载程序，查看 log 等。

# <span id = "aliyunprepare">3.生活物联网平台准备</span>
根据[生活物联网平台官方文档](https://help.aliyun.com/document_detail/126404.html?spm=a2c4g.11186623.6.562.4df61fd8UYppkg)，在生活物联网平台创建产品，创建设备，同时自动产生 `product key`, `product secert`, `device name`, `device secret`。  
`product key`, `product secert`, `device name`, `device secret` 将在 6.2.3 节用到。

# <span id = "compileprepare">4.环境搭建</span>
**如果您熟悉 ESP 开发环境，可以很顺利理解下面步骤; 如果您不熟悉某个部分，比如编译，烧录，需要您结合官方的相关文档来理解。如您需阅读 [ESP-IDF 编程指南](https://docs.espressif.com/projects/esp-idf/zh_CN/v4.2/index.html)文档等。**

## 4.1 编译器环境搭建
- ESP8266 平台: 根据[官方链接](https://github.com/espressif/ESP8266_RTOS_SDK)中 **Get toolchain**，获取 toolchain
- ESP32 & ESP32S2 平台：根据[官方链接](https://github.com/espressif/esp-idf/blob/master/docs/zh_CN/get-started/linux-setup.rst)中 **工具链的设置**，下载 toolchain

toolchain 设置参考 [ESP-IDF 编程指南](https://docs.espressif.com/projects/esp-idf/zh_CN/v4.2/get-started/index.html)。
## 4.2 烧录工具/下载工具获取
- ESP8266 平台：烧录工具位于 [ESP8266_RTOS_SDK](https://github.com/espressif/ESP8266_RTOS_SDK#get-toolchain) 下 `./components/esptool_py/esptool/esptool.py`
- ESP32 & ESP32S2 平台：烧录工具位于 [esp-idf](https://github.com/espressif/esp-idf) 下 `./components/esptool_py/esptool/esptool.py`

esptool 功能参考:  

```
$ ./components/esptool_py/esptool/esptool.py --help
```

# <span id = "sdkprepare">5.SDK 准备</span> 
- [esp-ali-smartliving SDK](https://github.com/espressif/esp-ali-smartliving), 通过该 SDK 可实现使用 MQTT 协议，连接 ESP 设备到阿里生活物联网平台。
- Espressif SDK
  - ESP32 & ESP32S2 平台: [ESP-IDF](https://github.com/espressif/esp-idf)
  - ESP8266 平台: [ESP8266_RTOS_SDK](https://github.com/espressif/ESP8266_RTOS_SDK)

> Espressif SDK 下载好后：  
> ESP-IDF: 请切换到 release v4.2 tag 版本： `git checkout v4.2`

> ESP8266_RTOS_SDK: 请切换到 v3.3 tag 版本： `git checkout v3.3`

# <span id = "makeflash">6.编译 & 烧写 & 运行</span>
## 6.1 编译

### 6.1.1 导出编译器
参考 [工具链的设置](https://docs.espressif.com/projects/esp-idf/zh_CN/v4.2/get-started/linux-setup.html)

### 6.1.2 编译 ali-smartliving-device-sdk-c 库
在 esp-ali-smartliving 目录下执行：

```
cd ali-smartliving-device-sdk-c
make reconfig (选择SDK平台)
make menuconfig (选择相关功能配置,默认不需要修改,该步骤可以省略)
make (生成相关头文件和库文件)
```

### 6.1.3 编译 demo 示例

在 esp-ali-smartliving 目录下执行：

```
cd examples/solutions/smart_light
make defconfig
make menuconfig
```
如果需要编译esp32s2版本, 请按照如下步骤编译:
执行如下命令，以 solo 示例为例，目前只支持 solo 和 smart_light 示例。

```
cd examples/solo/example_solo
idf.py set-target esp32s2
idf.py menuconfig
```

如果使用 cmake 编译 esp32，不需要 set-target。

- 配置烧写串口

2.生成最终 bin

```
make -j8
```
使用 esp32s2 生成 bin

```
idf.py build
```

### 6.1.4 使用 build shell 脚本编译运行

1. 按照第 4 节搭建好编译环境，配置好 SDK 路径。

2. 运行工程目录下 **build.sh** 文件，根据提示进行编译，当前该工具只支持 example_solo 和 smart_light 两个示例。

脚本可以支持包括：芯片 SDK 的选择，ali-smartliving-sdk-c 的编译配置，示例的编译。

按照提示执行，直至出现 **Now build all bin successfully!!!** 表示编译成功，可以按照提示进行烧录运行。
## 6.2 擦除 & 编译烧写 & 下载固件 & 查看 log
将 USB 线连接好 ESP 设备和 PC，确保烧写端口正确。 

### 6.2.1[可选] 擦除 flash
```
make erase_flash
```
使用 esp32s2 擦除 flash
```
idf.py -p (PORT) erase_flash
```
> 注：无需每次擦除，擦除后需要重做 6.2.3。

### 6.2.2 烧录程序
```
make flash
```

使用 esp32s2 烧录程序
```
idf.py -p (PORT) flash
```
### 6.2.3 烧录三元组信息
参考 [量产说明](./config/mass_mfg/README.md) 文档烧录三元组 NVS 分区。

## 6.2.4 运行

```
make monitor
```
使用 esp32s2 运行
```
idf.py -p (PORT) monitor
```
如将 ESP32 拨至运行状态，即可看到如下 log：
log 显示了 ESP32 基于 TLS 建立了与阿里生活物联网平台的安全连接通路，接着通过 MQTT 协议订阅和发布消息，同时在生活物联网平台控制台上，也能看到 ESP32 推送的 MQTT 消息。  

```
I (71) boot: Chip Revision: 1
I (72) boot_comm: chip revision: 1, min. bootloader chip revision: 0
I (39) boot: ESP-IDF v3.3.2-dirty 2nd stage bootloader
I (39) boot: compile time 15:16:58
I (39) boot: Enabling RNG early entropy source...
I (44) boot: SPI Speed      : 40MHz
I (48) boot: SPI Mode       : DIO
I (52) boot: SPI Flash Size : 4MB
I (57) boot: Partition Table:
I (60) boot: ## Label            Usage          Type ST Offset   Length
I (67) boot:  0 nvs              WiFi data        01 02 00009000 00004000
I (75) boot:  1 otadata          OTA data         01 00 0000d000 00002000
I (82) boot:  2 phy_init         RF data          01 01 0000f000 00001000
I (90) boot:  3 ota_0            OTA app          00 10 00010000 00100000
I (97) boot:  4 ota_1            OTA app          00 11 00110000 00100000
I (105) boot:  5 fctry            WiFi data        01 02 00210000 00004000
I (112) boot: End of partition table
I (117) boot_comm: chip revision: 1, min. application chip revision: 0
I (124) esp_image: segment 0: paddr=0x00010020 vaddr=0x3f400020 size=0x2cf14 (184084) map
I (197) esp_image: segment 1: paddr=0x0003cf3c vaddr=0x3ffb0000 size=0x030d4 ( 12500) load
I (203) esp_image: segment 2: paddr=0x00040018 vaddr=0x400d0018 size=0xaf604 (718340) map
I (456) esp_image: segment 3: paddr=0x000ef624 vaddr=0x3ffb30d4 size=0x00890 (  2192) load
I (457) esp_image: segment 4: paddr=0x000efebc vaddr=0x40080000 size=0x00400 (  1024) load
I (463) esp_image: segment 5: paddr=0x000f02c4 vaddr=0x40080400 size=0x14ee0 ( 85728) load
I (520) boot: Loaded app from partition at offset 0x10000
I (520) boot: Disabling RNG early entropy source...
I (521) cpu_start: Pro cpu up.
I (524) cpu_start: Application information:
I (529) cpu_start: Project name:     example_solo
I (534) cpu_start: App version:      v1.0-333-g8f389f0-dirty
I (541) cpu_start: Compile time:     May 22 2020 13:20:49
I (547) cpu_start: ELF file SHA256:  bfdd509082899884...
I (553) cpu_start: ESP-IDF:          v3.3.2-dirty
I (558) cpu_start: Starting app cpu, entry point is 0x400811d8
I (0) cpu_start: App cpu up.
I (568) heap_init: Initializing. RAM available for dynamic allocation:
I (575) heap_init: At 3FFAE6E0 len 00001920 (6 KiB): DRAM
I (581) heap_init: At 3FFBA9C0 len 00025640 (149 KiB): DRAM
I (588) heap_init: At 3FFE0440 len 00003AE0 (14 KiB): D/IRAM
I (594) heap_init: At 3FFE4350 len 0001BCB0 (111 KiB): D/IRAM
I (600) heap_init: At 400952E0 len 0000AD20 (43 KiB): IRAM
I (607) cpu_start: Pro cpu start user code
I (289) cpu_start: Starting scheduler on PRO CPU.
I (0) cpu_start: Starting scheduler on APP CPU.
I (370) wifi:wifi driver task: 3ffc296c, prio:23, stack:3584, core=0
I (370) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (370) system_api: Base MAC address is not set, read default base MAC address from BLK0 of EFUSE
I (400) wifi:wifi firmware version: 44aa95c
I (400) wifi:config NVS flash: enabled
I (400) wifi:config nano formating: disabled
I (400) wifi:Init dynamic tx buffer num: 32
I (410) wifi:Init data frame dynamic rx buffer num: 32
I (410) wifi:Init management frame dynamic rx buffer num: 32
I (420) wifi:Init management short buffer num: 32
I (420) wifi:Init static rx buffer size: 1600
I (430) wifi:Init static rx buffer num: 10
I (430) wifi:Init dynamic rx buffer num: 32
I (550) phy: phy_version: 4180, cb3948e, Sep 12 2019, 16:39:13, 0, 0
I (550) wifi:mode : sta (4c:11:ae:eb:8e:88)
[prt] log level set as: [ 4 ]
I (550) uart: queue free spaces: 1
....................................................
          DeviceName : test_004
        DeviceSecret : JmWp9zlCHSS5jbIvku6fJqTI44rSf4We
          ProductKey : a1QdKm5axuO
       ProductSecret : sUBuz3XD13sP083P
....................................................
I (580) conn_mgr: Found ssid HUAWEI-008
I (1070) wifi:new:<4,0>, old:<1,0>, ap:<255,255>, sta:<4,0>, prof:1
I (2050) wifi:state: init -> auth (b0)
I (2070) wifi:state: auth -> assoc (0)
I (2080) wifi:state: assoc -> run (10)
I (2130) wifi:connected with HUAWEI-008, aid = 1, channel 4, BW20, bssid = 34:29:12:43:c5:40
I (2130) wifi:security type: 3, phy: bg, rssi: -42
I (2130) wifi:pm start, type: 1

I (2150) wifi:AP's beacon interval = 102400 us, DTIM period = 1
I (3360) event: sta ip: 192.168.3.84, mask: 255.255.255.0, gw: 192.168.3.1
I (3370) conn_mgr: SNTP get time failed (0), retry after 1000 ms

I (4370) conn_mgr: SNTP get time success

[prt] log level set as: [ 4 ]
[inf] iotx_alcs_construct(454): iotx_alcs_construct enter
[inf] iotx_alcs_adapter_init(264): iotx_alcs_adapter_init
I (4470) udp: success to establish udp, fd=54
task name is CoAPServer_yield
[inf] alcs_context_init(241): CoAPServer_init return :0x3ffbc1b0
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/dev/a1QdKm5axuO/test_004/core/service/setup
[inf] alcs_resource_register_secure(639): alcs_resource_register_secure
W (4500) wrapper_kv: nvs get blob 5d6d2c84ee310cffec343f72b8c0a336 failed with 1102
[wrn] __alcs_localsetup_kv_get(45): HAL_Kv_Get('5d6d2c84ee310cffec343f72b8c0a336') = 4354 (!= 0), return 1
[wrn] alcs_localsetup_ac_as_load(147): ALCS KV Get local Prefix And Secret Fail
[inf] alcs_add_svr_key(260): alcs_add_svr_key, priority=0
[inf] add_svr_key(215): add_svr_key
[inf] CoAPServer_init(176): The CoAP Server already init
[inf] _dm_server_dev_notify(49): notify path:/dev/core/service/dev/notify; payload = {"id":"0","version":"1.0","params":{"devices":{"addr":"192.168.3.84","port":5683,"pal":"linkkit-ica","profile":[{"productKey":"a1QdKm5axuO","deviceName":"test_004"}]}},"method":"core.service.dev.notify"} ...
[inf] CoAPMessageList_add(390): add message 1 in list, keep:1, cur:1
[inf] CoAPMessageList_add(390): add message 2 in list, keep:1, cur:2
[inf] dm_client_open(37): CM Fd: 0
I (4590) app main: IOTX_CONN_CLOUD
....................................................
          ProductKey : a1QdKm5axuO
          DeviceName : test_004
            DeviceID : a1QdKm5axuO.test_004
....................................................
       PartnerID Buf : ,partner_id=espressif
        ModuleID Buf : ,module_id=wroom
          Guider URL : 
      Guider SecMode : 2 (TLS + Direct)
    Guider Timestamp : 2524608000000
....................................................
-----------------------------------------
            Host : a1QdKm5axuO.iot-as-mqtt.cn-shanghai.aliyuncs.com
            Port : 1883
        ClientID : a1QdKm5axuO.test_004|securemode=2,timestamp=2524608000000,signmethod=hmacsha1,gw=0,ext=0,partner_id=espressif,module_id=wroom,_fy=1.3.0,_ss=1|
      TLS PubKey : 0x3f411d21 ('-----BEGIN CERTI ...')
-----------------------------------------
[inf] iotx_mc_init(2379): MQTT init success!
[inf] iotx_mc_connect(2805): mqtt connect success!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /ota/device/request/a1QdKm5axuO/test_004!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /ota/device/upgrade/a1QdKm5axuO/test_004!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/config/get_reply!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/config/push!
[err] iotx_report_mid(402): No report MID because which has been reported within client id
[inf] iotx_redirect_region_subscribe(297): p_topic:/sys/a1QdKm5axuO/test_004/thing/bootstrap/config/push
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/bootstrap/config/push!
[inf] iotx_redirect_region_subscribe(303): sub success
[inf] _dm_client_event_cloud_connected_handle(133): IOTX_CM_EVENT_CLOUD_CONNECTED
I (6920) app main: IOTX_CONN_CLOUD_SUC
[inf] iotx_alcs_cloud_init(475): Start ALCS Cloud Init
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/lan/prefix/get_reply!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/lan/prefix/update!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/lan/blacklist/update!
[inf] alcs_mqtt_prefixkey_update(699): start alcs_prefixkey_update
W (6980) wrapper_kv: nvs get blob 5d6d2c84ee310cffec343f72b8c0a336 failed with 1102
[err] alcs_mqtt_prefix_secret_load(177): ALCS KV Get Prefix And Secret Fail
[inf] alcs_mqtt_prefixkey_update(708): alcs_prefixkey_update failed
[inf] __alcs_mqtt_kv_get(75): ALCS KV Get, Key: blacklist
[inf] alcs_mqtt_blacklist_update(676): The blacklist is eVR5lbNuibj5BdSY88
[inf] alcs_prefixkey_get(737): ALCS Prefix Get, Topic: /sys/a1QdKm5axuO/test_004/thing/lan/prefix/get, Payload: {"id":"0","version":"1.0","params":"{}","method":"thing.lan.prefix.get"}
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/sys/a1QdKm5axuO/test_004/thing/service/property/set
[inf] alcs_resource_register_secure(639): alcs_resource_register_secure
[inf] dm_server_subscribe(156): Register Resource Result: 0
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/sys/a1QdKm5axuO/test_004/thing/service/property/get
[inf] alcs_resource_register_secure(639): alcs_resource_register_secure
[inf] dm_server_subscribe(156): Register Resource Result: 0
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/sys/a1QdKm5axuO/test_004/thing/event/property/post
[inf] alcs_resource_register_secure(639): alcs_resource_register_secure
[inf] dm_server_subscribe(156): Register Resource Result: 0
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/sys/a1QdKm5axuO/test_004/thing/service/#
[inf] alcs_resource_register_secure(639): alcs_resource_register_secure
[inf] dm_server_subscribe(156): Register Resource Result: 0
[inf] iotx_alcs_register_resource(785): alcs register resource, uri:/dev/core/service/dev
[inf] dm_server_subscribe(156): Register Resource Result: 0
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/event/+/post_reply!
[err] iotx_cloud_conn_mqtt_event_handle(184): sub handle is null!
[inf] __alcs_mqtt_subscribe_callback(298): Receivce Message, Topic: /sys/a1QdKm5axuO/test_004/thing/lan/prefix/get_reply
[inf] __alcs_mqtt_subscribe_callback(314): Get Reply, Product Key: a1QdKm5axuO, Device Name: test_004, PrefixKey: fpCuGXgt
[inf] alcs_add_svr_key(260): alcs_add_svr_key, priority=2
[inf] add_svr_key(215): add_svr_key
[inf] dm_client_subscribe(101): Subscribe Result: 12
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/service/property/set!
[inf] dm_client_subscribe(101): Subscribe Result: 13
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/service/+!
[inf] dm_client_subscribe(101): Subscribe Result: 14
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/deviceinfo/update_reply!
[inf] dm_client_subscribe(101): Subscribe Result: 15
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/deviceinfo/delete_reply!
[inf] dm_client_subscribe(101): Subscribe Result: 16
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/_thing/event/notify!
[inf] dm_client_subscribe(101): Subscribe Result: 17
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/rrpc/request/+!
[inf] dm_client_subscribe(101): Subscribe Result: 18
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /ext/ntp/+/+/response!
[inf] dm_client_subscribe(101): Subscribe Result: 19
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /ext/error/+/+!
[inf] dm_client_subscribe(101): Subscribe Result: 20
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/model/down_raw!
[inf] dm_client_subscribe(101): Subscribe Result: 21
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/+/+/thing/model/up_raw_reply!
[inf] dm_client_subscribe(101): Subscribe Result: 22
[inf] iotx_dm_subscribe(218): Devid 0 Sub Completed
[inf] _iotx_linkkit_event_callback(237): Receive Message Type: 10
[inf] _iotx_linkkit_event_callback(239): Receive Message: {"devid":0}
user_initialized.305: Device Initialized, Devid: 0
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/awss/enrollee/match_reply!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/awss/enrollee/checkin!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/awss/enrollee/found_reply!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/cipher/get_reply!
[inf] iotx_mc_subscribe(2062): mqtt subscribe packet sent,topic = /sys/a1QdKm5axuO/test_004/thing/awss/device/switchap!
[inf] awss_report_token_to_cloud(367): report token res:28
[inf] CoAPServer_init(176): The CoAP Server already init
[inf] awss_bind_report_statis(72): bind report statis success
[inf] awss_report_token_reply(117): awss_report_token_reply
[inf] _iotx_linkkit_event_callback(237): Receive Message Type: 0
user_connected_event_handler.46: Cloud Connected
[inf] dm_msg_request(212): DM Send Message, URI: /sys/a1QdKm5axuO/test_004/thing/event/property/post, Payload: {"id":"3","version":"1.0","params":{"LightSwitch":1},"method":"thing.event.property.post"}
[inf] dm_client_publish(146): Publish Result: 0
[inf] dm_server_send(126): Send Observe Notify Result 0
user_post_property.351: Post Property Message ID: 3
[inf] dm_msg_request(212): DM Send Message, URI: /sys/a1QdKm5axuO/test_004/thing/event/Error/post, Payload: {"id":"4","version":"1.0","params":{"ErrorCode":0},"method":"thing.event.Error.post"}
[inf] dm_client_publish(146): Publish Result: 0
[inf] dm_server_send(126): Send Observe Notify Result 0
user_post_event.366: Post Event Message ID: 4
[inf] dm_msg_proc_thing_event_post_reply(362): Event Id: property
I (7860) app main: IOTX_AWSS_BIND_NOTIFY
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 3 in list, keep:1, cur:3
[inf] awss_notify_dev_info(235): coap send notify success
[inf] dm_msg_proc_thing_event_post_reply(362): Event Id: Error
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 4 in list, keep:1, cur:3
[inf] awss_notify_dev_info(235): coap send notify success
[inf] _iotx_linkkit_event_callback(237): Receive Message Type: 31
[inf] _iotx_linkkit_event_callback(239): Receive Message: {"id":3,"code":200,"devid":0,"payload":{}}
user_report_reply_event_handler.280: Message Post Reply Received, Devid: 0, Message ID: 3, Code: 200, Reply: {}
[inf] _iotx_linkkit_event_callback(237): Receive Message Type: 32
[inf] _iotx_linkkit_event_callback(239): Receive Message: {"id":4,"code":200,"devid":0,"eventid":"Error","payload":"success"}
user_trigger_event_reply_event_handler.290: Trigger Event Reply Received, Devid: 0, Message ID: 4, Code: 200, EventID: Error, Message: success
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 5 in list, keep:1, cur:3
[inf] awss_notify_dev_info(235): coap send notify success
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 6 in list, keep:1, cur:3
[inf] awss_notify_dev_info(235): coap send notify success
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 7 in list, keep:1, cur:3
[inf] awss_notify_dev_info(235): coap send notify success
[inf] awss_notify_dev_info(231): topic:/sys/device/info/notify
[inf] CoAPMessageList_add(390): add message 8 in list, keep:1, cur:3

```

> 也可执行 `make flash monitor` 来编译烧写和查看 log。
